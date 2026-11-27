import assert from 'node:assert/strict';
import zlib from 'node:zlib';

export function writeString(block, offset, length, value) {
  const bytes = Buffer.from(value, 'utf8');
  assert.ok(bytes.length <= length, 'test string does not fit tar field');
  bytes.copy(block, offset);
}

export function writeOctal(block, offset, length, value) {
  const digits = value.toString(8).padStart(length - 1, '0');
  assert.ok(digits.length <= length - 1, 'test octal value does not fit tar field');
  block.write(digits, offset, 'ascii');
  block[offset + digits.length] = 0;
}

export function makeHeader(input = {}) {
  const block = Buffer.alloc(512, 0);
  const name = input.headerName ?? input.name ?? '';
  writeString(block, 0, 100, name);
  writeOctal(block, 100, 8, input.mode ?? 0o644);
  writeOctal(block, 108, 8, input.uid ?? 0);
  writeOctal(block, 116, 8, input.gid ?? 0);
  writeOctal(block, 124, 12, input.size ?? 0);
  writeOctal(block, 136, 12, input.mtime ?? 1700000000);
  block.fill(0x20, 148, 156);
  const typeflag = input.typeflag ?? input.type ?? '0';
  block[156] = typeflag === '\0' ? 0 : typeflag.charCodeAt(0);
  writeString(block, 157, 100, input.linkname ?? '');
  const format = input.format ?? 'ustar';
  if (format === 'ustar' || format === 'pax') {
    block.write('ustar', 257, 'ascii');
    block[262] = 0;
    block.write('00', 263, 'ascii');
  } else if (format === 'gnu') {
    block.write('ustar ', 257, 'ascii');
    block[263] = 0x20;
    block[264] = 0;
  }
  writeString(block, 265, 32, input.uname ?? '');
  writeString(block, 297, 32, input.gname ?? '');
  writeOctal(block, 329, 8, input.devmajor ?? 0);
  writeOctal(block, 337, 8, input.devminor ?? 0);
  writeString(block, 345, 155, input.prefix ?? '');

  let sum = 0;
  for (const byte of block) sum += byte;
  const checksum = sum.toString(8).padStart(6, '0');
  block.write(checksum, 148, 'ascii');
  block[148 + checksum.length] = 0;
  block[154] = 0x20;
  return block;
}

export function paddingFor(size) {
  return (512 - (size % 512)) % 512;
}

export function entryParts(input) {
  const content = Buffer.isBuffer(input.content) ? input.content : Buffer.from(input.content ?? '');
  const size = input.size ?? content.length;
  const header = makeHeader({ ...input, size });
  const body = input.body === false ? Buffer.alloc(0) : content.subarray(0, size);
  return [header, body, Buffer.alloc(input.padding ?? paddingFor(size), input.paddingByte ?? 0)];
}

export function makeTar(entries, options = {}) {
  const parts = [];
  for (const entry of entries) parts.push(...entryParts(entry));
  const endBlocks = options.endBlocks ?? 2;
  for (let index = 0; index < endBlocks; index += 1) parts.push(Buffer.alloc(512, 0));
  if (options.trailing) parts.push(options.trailing);
  return Buffer.concat(parts);
}

export function paxPayload(records) {
  const chunks = [];
  for (const [key, value] of Object.entries(records)) {
    const body = Buffer.from(key + '=' + value + '\n', 'utf8');
    let digits = 1;
    let total = 0;
    while (true) {
      total = digits + 1 + body.length;
      const nextDigits = String(total).length;
      if (nextDigits === digits) break;
      digits = nextDigits;
    }
    chunks.push(Buffer.from(String(total) + ' ', 'ascii'), body);
  }
  return Buffer.concat(chunks);
}

export function paxEntry(records, options = {}) {
  const content = paxPayload(records);
  return {
    name: options.name ?? 'PaxHeaders/entry',
    typeflag: 'x',
    content,
    mode: 0o644,
    ...options
  };
}

export function gnuMetadata(typeflag, value, options = {}) {
  return {
    name: options.name ?? (typeflag === 'L' ? './@LongLink' : './@LongLinkTarget'),
    typeflag,
    content: Buffer.concat([Buffer.from(value, 'utf8'), Buffer.alloc(1)]),
    ...options
  };
}

export function file(name, content = '', options = {}) {
  return { name, typeflag: '0', content, ...options };
}

export function directory(name, options = {}) {
  return { name, typeflag: '5', content: '', size: 0, mode: 0o755, ...options };
}

export function symlink(name, linkname, options = {}) {
  return { name, typeflag: '2', linkname, content: '', size: 0, ...options };
}

export function hardlink(name, linkname, options = {}) {
  return { name, typeflag: '1', linkname, content: '', size: 0, ...options };
}

export function gzip(buffer) {
  return zlib.gzipSync(buffer, { level: 9 });
}

export function repairFirstHeaderChecksum(buffer) {
  const copy = Buffer.from(buffer);
  copy.fill(0x20, 148, 156);
  let sum = 0;
  for (const byte of copy.subarray(0, 512)) sum += byte;
  const checksum = sum.toString(8).padStart(6, '0');
  copy.write(checksum, 148, 'ascii');
  copy[148 + checksum.length] = 0;
  copy[154] = 0x20;
  return copy;
}

export function patchFirstHeader(buffer, offset, bytes) {
  const copy = Buffer.from(buffer);
  Buffer.from(bytes).copy(copy, offset);
  return repairFirstHeaderChecksum(copy);
}

export function octalText(value, length) {
  return value.toString(8).padStart(length - 1, '0') + '\0';
}

export function patch(buffer, offset, value) {
  const copy = Buffer.from(buffer);
  copy[offset] = value;
  return copy;
}

export function patchRange(buffer, offset, bytes) {
  const copy = Buffer.from(buffer);
  Buffer.from(bytes).copy(copy, offset);
  return copy;
}

export function findingCodes(report) {
  return report.findings.map((finding) => finding.code);
}

export function hasFinding(report, code) {
  return report.findings.some((finding) => finding.code === code);
}

export async function expectTarError(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.equal(error.code, code);
    return true;
  });
}
