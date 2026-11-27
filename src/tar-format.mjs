import { TARCAGE_ERROR_CODES as C, TarChecksumError, TarFormatError } from './errors.mjs';
import { isForbiddenObjectKey } from './path-security.mjs';

const TEXT_DECODER = new TextDecoder('utf-8', { fatal: true });
const TEXT_DECODER_LENIENT = new TextDecoder('utf-8', { fatal: false });
const ASCII_DECODER = new TextDecoder('ascii', { fatal: true });
const STRICT_PAX_VALUE_KEYS = new Set(['path', 'linkpath', 'size']);
const MAX_SAFE_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);
const PAX_KEY_RE = /^[A-Za-z0-9._-]+$/;
const UNSUPPORTED_PAX_KEYS = new Set(['GNU.sparse', 'GNU.dumpdir', 'SCHILY.filetype']);

export function isZeroBlock(block) {
  if (!block || block.length === 0) return false;
  for (const byte of block) {
    if (byte !== 0) return false;
  }
  return true;
}

function decodeUtf8(bytes, fieldName, details) {
  try {
    return TEXT_DECODER.decode(bytes);
  } catch (error) {
    throw new TarFormatError(C.INVALID_ENCODING, fieldName + ' is not valid UTF-8', details, error);
  }
}

function decodeAscii(bytes, fieldName, details) {
  try {
    return ASCII_DECODER.decode(bytes);
  } catch (error) {
    throw new TarFormatError(C.INVALID_ENCODING, fieldName + ' is not valid ASCII', details, error);
  }
}

export function readCString(bytes, fieldName, details) {
  const nul = bytes.indexOf(0);
  const end = nul === -1 ? bytes.length : nul;
  for (let index = end; index < bytes.length; index += 1) {
    if (bytes[index] !== 0) {
      throw new TarFormatError(C.MALFORMED_ARCHIVE, fieldName + ' contains bytes after its NUL terminator', details);
    }
  }
  return decodeUtf8(bytes.subarray(0, end), fieldName, details);
}

export function parseNumericField(bytes, fieldName, details = {}) {
  if (bytes.length === 0) return 0;

  if ((bytes[0] & 0x80) !== 0) {
    if (bytes[0] === 0xff) {
      throw new TarFormatError(C.NUMERIC_FIELD, fieldName + ' is a negative base-256 number', details);
    }
    let value = BigInt(bytes[0] & 0x7f);
    for (let index = 1; index < bytes.length; index += 1) {
      value = (value << 8n) | BigInt(bytes[index]);
    }
    if (value > MAX_SAFE_BIGINT) {
      throw new TarFormatError(C.NUMERIC_FIELD, fieldName + ' overflows the safe integer range', details);
    }
    return Number(value);
  }

  let start = 0;
  let end = bytes.length;
  while (end > start && (bytes[end - 1] === 0 || bytes[end - 1] === 0x20)) end -= 1;
  while (start < end && bytes[start] === 0x20) start += 1;
  if (start === end) return 0;
  if (end === bytes.length) {
    throw new TarFormatError(C.NUMERIC_FIELD, fieldName + ' is missing its required NUL or space terminator', details);
  }

  let value = 0n;
  for (let index = start; index < end; index += 1) {
    const byte = bytes[index];
    if (byte < 0x30 || byte > 0x37) {
      const negative = byte === 0x2d ? 'negative ' : '';
      throw new TarFormatError(C.NUMERIC_FIELD, fieldName + ' is not a valid ' + negative + 'octal number', details);
    }
    value = (value << 3n) | BigInt(byte - 0x30);
    if (value > MAX_SAFE_BIGINT) {
      throw new TarFormatError(C.NUMERIC_FIELD, fieldName + ' overflows the safe integer range', details);
    }
  }
  return Number(value);
}

function checksums(block) {
  let unsigned = 0;
  let signed = 0;
  for (let index = 0; index < 512; index += 1) {
    const byte = index >= 148 && index < 156 ? 0x20 : block[index];
    unsigned += byte;
    signed += byte >= 128 ? byte - 256 : byte;
  }
  return { unsigned, signed };
}

function headerMagic(block) {
  const magic = block.subarray(257, 263);
  if (magic[0] === 0x75 && magic[1] === 0x73 && magic[2] === 0x74 && magic[3] === 0x61 && magic[4] === 0x72) {
    if (magic[5] === 0 && block[263] === 0x30 && block[264] === 0x30) return 'ustar';
    if (magic[5] === 0x20 && block[263] === 0x20 && block[264] === 0) return 'gnu';
  }
  let zero = true;
  for (const byte of magic) {
    if (byte !== 0) zero = false;
  }
  if (zero) return 'v7';
  return 'unknown';
}

export function parseTarHeader(block, offset, policy) {
  const details = { offset };
  if (!Buffer.isBuffer(block) || block.length !== 512) {
    throw new TarFormatError(C.MALFORMED_ARCHIVE, 'header block must contain exactly 512 bytes', details);
  }

  const format = headerMagic(block);
  if (format === 'unknown') {
    throw new TarFormatError(C.MALFORMED_ARCHIVE, 'header magic is not POSIX ustar, GNU tar, or zeroed V7 format', details);
  }

  const storedChecksum = parseNumericField(block.subarray(148, 156), 'checksum', details);
  const sums = checksums(block);
  let signedChecksumLegacy = false;
  if (policy.strictChecksum && storedChecksum !== sums.unsigned) {
    if (storedChecksum === sums.signed && policy.allowSignedChecksums) {
      signedChecksumLegacy = true;
    } else {
      throw new TarChecksumError(C.CHECKSUM_MISMATCH, 'header checksum verification failed', {
        offset,
        stored: storedChecksum,
        unsigned: sums.unsigned
      });
    }
  }

  const name = readCString(block.subarray(0, 100), 'header name', details);
  const mode = parseNumericField(block.subarray(100, 108), 'mode', details);
  const uid = parseNumericField(block.subarray(108, 116), 'uid', details);
  const gid = parseNumericField(block.subarray(116, 124), 'gid', details);
  const size = parseNumericField(block.subarray(124, 136), 'size', details);
  const mtime = parseNumericField(block.subarray(136, 148), 'mtime', details);
  const typeByte = block[156];
  const typeflag = typeByte === 0 ? '\0' : String.fromCharCode(typeByte);
  const linkname = readCString(block.subarray(157, 257), 'header linkname', details);
  const uname = readCString(block.subarray(265, 297), 'header uname', details);
  const gname = readCString(block.subarray(297, 329), 'header gname', details);
  const devmajor = parseNumericField(block.subarray(329, 337), 'devmajor', details);
  const devminor = parseNumericField(block.subarray(337, 345), 'devminor', details);
  const prefix = readCString(block.subarray(345, 500), 'header prefix', details);

  let fullName = name;
  if (format !== 'v7' && prefix.length > 0) {
    fullName = prefix + '/' + name;
  }

  return {
    offset,
    format,
    name: fullName,
    rawName: name,
    prefix,
    mode,
    uid,
    gid,
    size,
    mtime,
    typeflag,
    linkname,
    uname,
    gname,
    devmajor,
    devminor,
    signedChecksumLegacy
  };
}

export function parsePaxPayload(payload, details = {}) {
  const records = new Map();
  let position = 0;

  while (position < payload.length) {
    let space = -1;
    const digitLimit = Math.min(position + 24, payload.length);
    for (let index = position; index < digitLimit; index += 1) {
      if (payload[index] === 0x20) {
        space = index;
        break;
      }
      if (payload[index] < 0x30 || payload[index] > 0x39) {
        throw new TarFormatError(C.PAX_FORMAT, 'PAX record length contains a non-decimal byte', details);
      }
    }
    if (space === -1 || space === position) {
      throw new TarFormatError(C.PAX_FORMAT, 'PAX record is missing a decimal length', details);
    }

    const lengthText = decodeAscii(payload.subarray(position, space), 'PAX record length', details);
    if (lengthText.length > 1 && lengthText.startsWith('0')) {
      throw new TarFormatError(C.PAX_FORMAT, 'PAX record length has a non-canonical leading zero', details);
    }
    const recordLength = Number(lengthText);
    if (!Number.isSafeInteger(recordLength) || recordLength < 3) {
      throw new TarFormatError(C.PAX_FORMAT, 'PAX record length is invalid', details);
    }
    const end = position + recordLength;
    if (end > payload.length) {
      throw new TarFormatError(C.PAX_FORMAT, 'PAX record length overruns the extended header payload', details);
    }
    if (payload[end - 1] !== 0x0a) {
      throw new TarFormatError(C.PAX_FORMAT, 'PAX record does not end with a newline', details);
    }

    const body = payload.subarray(space + 1, end - 1);
    const equals = body.indexOf(0x3d);
    if (equals <= 0) {
      throw new TarFormatError(C.PAX_FORMAT, 'PAX record is missing a key separator', details);
    }
    const key = decodeAscii(body.subarray(0, equals), 'PAX key', details);
    if (!PAX_KEY_RE.test(key) || isForbiddenObjectKey(key)) {
      throw new TarFormatError(C.PAX_FORMAT, 'PAX key is not portable or is forbidden', { ...details, key });
    }
    if (UNSUPPORTED_PAX_KEYS.has(key) || key.startsWith('GNU.sparse.')) {
      throw new TarFormatError(C.UNSUPPORTED_EXTENSION, 'unsupported PAX extension key changes extraction semantics', { ...details, key });
    }
    if (records.has(key)) {
      throw new TarFormatError(C.PAX_FORMAT, 'duplicate PAX key in one extended header', { ...details, key });
    }
    const valueBytes = body.subarray(equals + 1);
    const value = STRICT_PAX_VALUE_KEYS.has(key)
      ? decodeUtf8(valueBytes, 'PAX value', { ...details, key })
      : TEXT_DECODER_LENIENT.decode(valueBytes);
    records.set(key, value);
    position = end;
  }

  return records;
}

export function parsePaxSize(value, details = {}) {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new TarFormatError(C.PAX_FORMAT, 'PAX size must be canonical decimal ASCII', details);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new TarFormatError(C.NUMERIC_FIELD, 'PAX size overflows the safe integer range', details);
  }
  return parsed;
}

export function parseGnuNamePayload(payload, kind, details = {}) {
  if (payload.length === 0 || payload[payload.length - 1] !== 0) {
    throw new TarFormatError(C.GNU_METADATA, kind + ' payload must end with one NUL byte', details);
  }
  for (let index = 0; index < payload.length - 1; index += 1) {
    if (payload[index] === 0) {
      throw new TarFormatError(C.GNU_METADATA, kind + ' payload contains an interior NUL byte', details);
    }
  }
  const value = decodeUtf8(payload.subarray(0, payload.length - 1), kind, details);
  if (value.length === 0) {
    throw new TarFormatError(C.GNU_METADATA, kind + ' payload cannot be empty', details);
  }
  return value;
}

export function typeflagName(typeflag) {
  if (typeflag === '\0' || typeflag === '0') return 'file';
  if (typeflag === '1') return 'hardlink';
  if (typeflag === '2') return 'symlink';
  if (typeflag === '3') return 'character-device';
  if (typeflag === '4') return 'block-device';
  if (typeflag === '5') return 'directory';
  if (typeflag === '6') return 'fifo';
  if (typeflag === '7') return 'contiguous-file';
  if (typeflag === 'x') return 'pax-entry-header';
  if (typeflag === 'g') return 'pax-global-header';
  if (typeflag === 'L') return 'gnu-longname';
  if (typeflag === 'K') return 'gnu-longlink';
  return 'unknown';
}

export function paxRecordsObject(records) {
  const output = Object.create(null);
  for (const [key, value] of records) output[key] = value;
  return output;
}
