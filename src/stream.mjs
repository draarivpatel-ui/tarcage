import { createHash } from 'node:crypto';
import { promises as fs, createReadStream } from 'node:fs';
import { Readable, Transform } from 'node:stream';
import { createGunzip } from 'node:zlib';
import { TARCAGE_ERROR_CODES as C, TarCageError, TarFormatError, TarInputError, TarLimitError } from './errors.mjs';

const MIN_RATIO_SAMPLE_BYTES = 1024 * 1024;
const GZIP_MAGIC_0 = 0x1f;
const GZIP_MAGIC_1 = 0x8b;

function inputError(message, details, cause) {
  throw new TarInputError(C.INVALID_INPUT, message, details, cause);
}

function byteInput(input) {
  if (Buffer.isBuffer(input)) return input;
  if (input instanceof Uint8Array) return Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  return null;
}

function* bufferChunks(buffer) {
  const step = 64 * 1024;
  for (let offset = 0; offset < buffer.length; offset += step) {
    yield buffer.subarray(offset, Math.min(buffer.length, offset + step));
  }
}

async function pathStartsWithGzip(filePath) {
  let handle;
  try {
    handle = await fs.open(filePath, 'r');
    const header = Buffer.alloc(2);
    const { bytesRead } = await handle.read(header, 0, 2, 0);
    return bytesRead === 2 && header[0] === GZIP_MAGIC_0 && header[1] === GZIP_MAGIC_1;
  } catch (error) {
    throw new TarInputError(C.INPUT_IO, 'cannot open archive input', { inputType: 'path' }, error);
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}

function makeCounter(policy, state, kind) {
  return new Transform({
    highWaterMark: 64 * 1024,
    transform(chunk, encoding, callback) {
      try {
        if (kind === 'compressed') {
          state.compressedBytes += chunk.length;
          if (state.compressedBytes > policy.maxCompressedBytes) {
            throw new TarLimitError(C.COMPRESSED_LIMIT, 'compressed input exceeds maxCompressedBytes', {
              compressedBytes: state.compressedBytes,
              maxCompressedBytes: policy.maxCompressedBytes
            });
          }
        } else {
          state.uncompressedBytes += chunk.length;
          state.hash.update(chunk);
          if (!state.compressed) {
            state.compressedBytes += chunk.length;
            if (state.compressedBytes > policy.maxCompressedBytes) {
              throw new TarLimitError(C.COMPRESSED_LIMIT, 'input exceeds maxCompressedBytes', {
                compressedBytes: state.compressedBytes,
                maxCompressedBytes: policy.maxCompressedBytes
              });
            }
          }
          if (state.uncompressedBytes > policy.maxUncompressedBytes) {
            throw new TarLimitError(C.UNCOMPRESSED_LIMIT, 'uncompressed archive exceeds maxUncompressedBytes', {
              uncompressedBytes: state.uncompressedBytes,
              maxUncompressedBytes: policy.maxUncompressedBytes
            });
          }
          if (
            state.compressed &&
            state.uncompressedBytes >= MIN_RATIO_SAMPLE_BYTES &&
            state.compressedBytes > 0 &&
            state.uncompressedBytes / state.compressedBytes > policy.maxCompressionRatio
          ) {
            throw new TarLimitError(C.RATIO_LIMIT, 'gzip compression ratio exceeds maxCompressionRatio', {
              compressedBytes: state.compressedBytes,
              uncompressedBytes: state.uncompressedBytes,
              ratio: state.uncompressedBytes / state.compressedBytes,
              maxCompressionRatio: policy.maxCompressionRatio
            });
          }
        }
        callback(null, chunk);
      } catch (error) {
        callback(error);
      }
    }
  });
}

function wireStreamErrors(streams, state) {
  const fail = (error) => {
    if (!state.streamError) state.streamError = error;
    for (const stream of streams) {
      if (!stream.destroyed) stream.destroy(error);
    }
  };
  for (const stream of streams) {
    stream.on('error', fail);
  }
}

export async function openArchiveInput(input, policy) {
  const state = {
    compressed: false,
    compressedBytes: 0,
    uncompressedBytes: 0,
    hash: createHash('sha256'),
    streamError: null
  };

  let source;
  const bytes = byteInput(input);
  if (bytes !== null) {
    if (policy.compressed === 'auto') {
      state.compressed = bytes.length >= 2 && bytes[0] === GZIP_MAGIC_0 && bytes[1] === GZIP_MAGIC_1;
    } else {
      state.compressed = policy.compressed;
    }
    source = Readable.from(bufferChunks(bytes), { highWaterMark: 64 * 1024 });
  } else if (typeof input === 'string' && input.length > 0) {
    if (policy.compressed === 'auto') {
      state.compressed = await pathStartsWithGzip(input);
    } else {
      state.compressed = policy.compressed;
    }
    try {
      source = createReadStream(input, { highWaterMark: 64 * 1024 });
    } catch (error) {
      throw new TarInputError(C.INPUT_IO, 'cannot open archive input', { inputType: 'path' }, error);
    }
  } else {
    inputError('input must be a Buffer, Uint8Array, or archive file path', { inputType: typeof input });
  }

  const compressedCounter = makeCounter(policy, state, 'compressed');
  const uncompressedCounter = makeCounter(policy, state, 'uncompressed');
  let output;
  let streams;
  if (state.compressed) {
    const gunzip = createGunzip({ chunkSize: 64 * 1024 });
    output = source.pipe(compressedCounter).pipe(gunzip).pipe(uncompressedCounter);
    streams = [source, compressedCounter, gunzip, uncompressedCounter];
  } else {
    output = source.pipe(uncompressedCounter);
    streams = [source, uncompressedCounter];
  }
  wireStreamErrors(streams, state);

  return {
    stream: output,
    state,
    destroy(error) {
      for (const stream of streams) {
        if (!stream.destroyed) stream.destroy(error);
      }
    },
    finish() {
      if (state.digest) return state.digest;
      state.digest = state.hash.digest('hex');
      return state.digest;
    }
  };
}

function convertReadError(error, compressed) {
  if (error instanceof TarCageError) return error;
  if (compressed) {
    return new TarFormatError(C.GZIP_ERROR, 'gzip stream is malformed or truncated', undefined, error);
  }
  return new TarInputError(C.INPUT_IO, 'archive input stream failed', undefined, error);
}

export class ChunkReader {
  constructor(stream, compressed) {
    this.iterator = stream[Symbol.asyncIterator]();
    this.compressed = compressed;
    this.current = null;
    this.offset = 0;
    this.done = false;
    this.bytesRead = 0;
  }

  async readSome(maxBytes) {
    if (maxBytes < 1) return Buffer.alloc(0);
    while (this.current === null || this.offset >= this.current.length) {
      if (this.done) return null;
      let next;
      try {
        next = await this.iterator.next();
      } catch (error) {
        throw convertReadError(error, this.compressed);
      }
      if (next.done) {
        this.done = true;
        this.current = null;
        return null;
      }
      this.current = Buffer.isBuffer(next.value) ? next.value : Buffer.from(next.value);
      this.offset = 0;
    }

    const amount = Math.min(maxBytes, this.current.length - this.offset);
    const output = this.current.subarray(this.offset, this.offset + amount);
    this.offset += amount;
    this.bytesRead += amount;
    return output;
  }

  async readBlock(size, context) {
    const parts = [];
    let total = 0;
    while (total < size) {
      const chunk = await this.readSome(size - total);
      if (chunk === null) break;
      parts.push(chunk);
      total += chunk.length;
    }
    if (total === 0) return Buffer.alloc(0);
    if (total < size) {
      throw new TarFormatError(C.TRUNCATED_ARCHIVE, context + ' is truncated', { expected: size, actual: total });
    }
    return Buffer.concat(parts, size);
  }

  async readExact(size, context) {
    if (size === 0) return Buffer.alloc(0);
    const block = await this.readBlock(size, context);
    if (block.length !== size) {
      throw new TarFormatError(C.TRUNCATED_ARCHIVE, context + ' is truncated', { expected: size, actual: block.length });
    }
    return block;
  }

  async skipExact(size, context) {
    let remaining = size;
    while (remaining > 0) {
      const chunk = await this.readSome(Math.min(64 * 1024, remaining));
      if (chunk === null) {
        throw new TarFormatError(C.TRUNCATED_ARCHIVE, context + ' is truncated', { expected: size, actual: size - remaining });
      }
      remaining -= chunk.length;
    }
  }
}
