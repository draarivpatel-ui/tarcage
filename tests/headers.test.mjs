import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectTar, parseTar } from '../src/index.mjs';
import {
  expectTarError,
  file,
  gnuMetadata,
  hardlink,
  makeHeader,
  makeTar,
  patchFirstHeader,
  paxEntry,
  paxPayload,
  repairFirstHeaderChecksum,
  symlink
} from './helpers.mjs';

function rawPaxRecord(key, value) {
  const body = Buffer.concat([Buffer.from(key + '=', 'utf8'), Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8'), Buffer.from('\n')]);
  let digits = 1;
  while (true) {
    const total = digits + 1 + body.length;
    if (String(total).length === digits) return Buffer.concat([Buffer.from(String(total) + ' '), body]);
    digits = String(total).length;
  }
}

function signedChecksumArchive() {
  const header = makeHeader({ name: 'signed.txt', size: 1, uname: 'é' });
  header.fill(0x20, 148, 156);
  let signed = 0;
  for (const byte of header) signed += byte >= 128 ? byte - 256 : byte;
  const text = signed.toString(8).padStart(6, '0');
  header.write(text, 148, 'ascii');
  header[148 + text.length] = 0;
  header[154] = 0x20;
  return Buffer.concat([header, Buffer.from('x'), Buffer.alloc(511), Buffer.alloc(1024)]);
}

function writeBase256(block, offset, length, value) {
  block.fill(0, offset, offset + length);
  block[offset] = 0x80;
  let remaining = BigInt(value);
  for (let index = offset + length - 1; index > offset; index -= 1) {
    block[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
}

function archiveWithFirstHeaderPatch(offset, bytes) {
  return patchFirstHeader(makeTar([file('a', 'x')]), offset, bytes);
}

test('valid unsigned checksum is accepted', async () => {
  const report = await inspectTar(makeTar([file('ok', 'x')]));
  assert.equal(report.safe, true);
});

test('corrupted unsigned checksum is rejected', async () => {
  const archive = Buffer.from(makeTar([file('ok', 'x')]));
  archive[0] = archive[0] === 0x61 ? 0x62 : 0x61;
  const report = await inspectTar(archive);
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_CHECKSUM_MISMATCH');
});

test('strictChecksum false accepts a corrupted checksum for research use', async () => {
  const archive = Buffer.from(makeTar([file('ok', 'x')]));
  archive[0] = archive[0] === 0x61 ? 0x62 : 0x61;
  const report = await inspectTar(archive, { strictChecksum: false });
  assert.equal(report.safe, true);
});

test('legacy signed checksum is rejected by default', async () => {
  const report = await inspectTar(signedChecksumArchive());
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_CHECKSUM_MISMATCH');
});

test('legacy signed checksum can be explicitly allowed with a warning', async () => {
  const report = await inspectTar(signedChecksumArchive(), { allowSignedChecksums: true });
  assert.equal(report.safe, true);
  assert.equal(report.findings[0].severity, 'warning');
  assert.equal(report.entries[0].name, 'signed.txt');
});

test('parseTar throws checksum errors as TarChecksumError subclass instances', async () => {
  const archive = Buffer.from(makeTar([file('ok', 'x')]));
  archive[0] = archive[0] === 0x61 ? 0x62 : 0x61;
  await assert.rejects(parseTar(archive), (error) => error.name === 'TarChecksumError' && error.code === 'TARCAGE_CHECKSUM_MISMATCH');
});

const numericFields = [
  ['mode', 100, 8],
  ['uid', 108, 8],
  ['gid', 116, 8],
  ['size', 124, 12],
  ['mtime', 136, 12],
  ['devmajor', 329, 8],
  ['devminor', 337, 8]
];

for (const [field, offset, length] of numericFields) {
  test('numeric field ' + field + ' accepts leading spaces', async () => {
    const digits = field === 'size' ? '1' : '0';
    const text = ' '.repeat(length - digits.length - 1) + digits + '\0';
    const archive = archiveWithFirstHeaderPatch(offset, text);
    const report = await inspectTar(archive);
    assert.equal(report.safe, true);
  });

  test('numeric field ' + field + ' rejects non-octal digit 9', async () => {
    const text = '9'.repeat(length - 1) + '\0';
    const report = await inspectTar(archiveWithFirstHeaderPatch(offset, text));
    assert.equal(report.safe, false);
    assert.equal(report.findings[0].code, 'TARCAGE_NUMERIC_FIELD');
  });

  test('numeric field ' + field + ' rejects negative sign syntax', async () => {
    const text = '-1' + '0'.repeat(length - 3) + '\0';
    const report = await inspectTar(archiveWithFirstHeaderPatch(offset, text));
    assert.equal(report.safe, false);
    assert.equal(report.findings[0].code, 'TARCAGE_NUMERIC_FIELD');
  });
}

test('empty numeric size field is treated as zero and then fails truncation normally', async () => {
  const archive = archiveWithFirstHeaderPatch(124, ' '.repeat(11) + '\0');
  const report = await inspectTar(archive);
  assert.equal(report.safe, false);
});

test('positive base-256 size field is accepted', async () => {
  const archive = Buffer.from(makeTar([file('a', 'hello')]));
  writeBase256(archive, 124, 12, 5);
  const repaired = repairFirstHeaderChecksum(archive);
  const report = await inspectTar(repaired);
  assert.equal(report.safe, true);
  assert.equal(report.entries[0].size, 5);
});

test('negative base-256 size field is rejected', async () => {
  const archive = Buffer.from(makeTar([file('a', 'hello')]));
  archive.fill(0xff, 124, 136);
  const repaired = repairFirstHeaderChecksum(archive);
  const report = await inspectTar(repaired);
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_NUMERIC_FIELD');
});

test('overflowing base-256 numeric field is rejected', async () => {
  const archive = Buffer.from(makeTar([file('a', 'hello')]));
  archive.fill(0, 124, 136);
  archive[124] = 0x90;
  archive[135] = 1;
  const repaired = repairFirstHeaderChecksum(archive);
  const report = await inspectTar(repaired);
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_NUMERIC_FIELD');
});

test('overflowing octal numeric field is rejected', async () => {
  const archive = archiveWithFirstHeaderPatch(124, '77777777777\0');
  const report = await inspectTar(archive);
  assert.equal(report.safe, false);
});

test('unknown header magic is rejected', async () => {
  const report = await inspectTar(archiveWithFirstHeaderPatch(257, 'notart'));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_MALFORMED_ARCHIVE');
});

test('non-zero bytes after a string NUL terminator are rejected', async () => {
  const report = await inspectTar(archiveWithFirstHeaderPatch(290, 'Z'));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_MALFORMED_ARCHIVE');
});

for (const count of [0, 1]) {
  test('strict EOF requires two zero blocks, case ' + count, async () => {
    const report = await inspectTar(makeTar([file('a', 'x')], { endBlocks: count }));
    assert.equal(report.safe, false);
    assert.equal(report.findings[0].code, 'TARCAGE_EOF_MISSING');
  });
}

test('strictEof false accepts a complete entry without end blocks', async () => {
  const report = await inspectTar(makeTar([file('a', 'x')], { endBlocks: 0 }), { strictEof: false });
  assert.equal(report.safe, true);
});

test('non-zero trailing data after two end blocks is a polyglot finding', async () => {
  const archive = makeTar([file('a', 'x')], { trailing: Buffer.alloc(512, 1) });
  const report = await inspectTar(archive);
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_TRAILING_DATA');
});

test('zero padding after end markers is accepted', async () => {
  const archive = makeTar([file('a', 'x')], { trailing: Buffer.alloc(1024, 0) });
  const report = await inspectTar(archive);
  assert.equal(report.safe, true);
  assert.equal(report.stats.endMarkers >= 4, true);
});

test('a single zero block interrupted by a header is malformed', async () => {
  const archive = Buffer.concat([Buffer.alloc(512), makeTar([file('a', 'x')], { endBlocks: 0 })]);
  const report = await inspectTar(archive);
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_MALFORMED_ARCHIVE');
});

test('non-zero file padding is rejected by default', async () => {
  const archive = makeTar([file('a', 'abc', { paddingByte: 1 })]);
  const report = await inspectTar(archive);
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_PADDING_CORRUPT');
});

test('strictPadding false accepts non-zero file padding', async () => {
  const archive = makeTar([file('a', 'abc', { paddingByte: 1 })]);
  const report = await inspectTar(archive, { strictPadding: false });
  assert.equal(report.safe, true);
});

for (const size of [1, 2, 511, 512, 513, 1024]) {
  test('entry padding is consumed correctly for size ' + size, async () => {
    const content = Buffer.alloc(size, 65);
    const report = await inspectTar(makeTar([file('a', content)]));
    assert.equal(report.safe, true);
    assert.equal(report.entries[0].size, size);
  });
}

test('truncated entry data is rejected', async () => {
  const archive = makeTar([file('a', 'abcdef')]).subarray(0, 512 + 3);
  const report = await inspectTar(archive);
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_TRUNCATED_ARCHIVE');
});

test('truncated header block is rejected', async () => {
  const report = await inspectTar(makeTar([file('a', 'x')]).subarray(0, 200));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_TRUNCATED_ARCHIVE');
});

test('valid unknown PAX metadata key is preserved', async () => {
  const report = await inspectTar(makeTar([paxEntry({ comment: 'hello' }), file('a', 'x')]));
  assert.equal(report.safe, true);
  assert.equal(report.entries[0].pax.comment, 'hello');
});

test('binary unknown PAX metadata is tolerated because it is ignored', async () => {
  const payload = rawPaxRecord('VENDOR.binary', Buffer.from([1, 2, 255, 3]));
  const report = await inspectTar(makeTar([{ name: 'px', typeflag: 'x', content: payload }, file('a', 'x')]));
  assert.equal(report.safe, true);
});

test('invalid UTF-8 in PAX path is rejected', async () => {
  const payload = rawPaxRecord('path', Buffer.from([0xff, 0xfe]));
  const report = await inspectTar(makeTar([{ name: 'px', typeflag: 'x', content: payload }, file('a', 'x')]));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_INVALID_ENCODING');
});

test('PAX long path overrides a truncated header path', async () => {
  const longPath = 'dir/' + 'x'.repeat(130);
  const report = await inspectTar(makeTar([
    paxEntry({ path: longPath }),
    file('ignored', 'x', { headerName: longPath.slice(0, 100) })
  ]));
  assert.equal(report.safe, true);
  assert.equal(report.entries[0].name, longPath);
});

test('PAX path conflicting with a short header path is rejected', async () => {
  const report = await inspectTar(makeTar([paxEntry({ path: 'safe.txt' }), file('evil.txt', 'x')]));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_PAX_CONFLICT');
});

test('PAX size equal to the header size is accepted', async () => {
  const report = await inspectTar(makeTar([paxEntry({ size: '1' }), file('a', 'x')]));
  assert.equal(report.safe, true);
});

for (const size of ['0', '2', '999']) {
  test('conflicting PAX size ' + size + ' is rejected', async () => {
    const report = await inspectTar(makeTar([paxEntry({ size }), file('a', 'x')]));
    assert.equal(report.safe, false);
    assert.equal(report.findings[0].code, 'TARCAGE_PAX_CONFLICT');
  });
}

test('PAX linkpath agreeing with header is accepted', async () => {
  const report = await inspectTar(makeTar([paxEntry({ linkpath: 'target' }), symlink('ln', 'target')]), { allowSymlinks: true });
  assert.equal(report.safe, true);
});

test('PAX linkpath conflicting with header is rejected', async () => {
  const report = await inspectTar(makeTar([paxEntry({ linkpath: 'other' }), symlink('ln', 'target')]), { allowSymlinks: true });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_PAX_CONFLICT');
});

const malformedPaxPayloads = [
  ['nondecimal length', Buffer.from('x a=b\n')],
  ['leading zero length', Buffer.from('06 a=b\n')],
  ['overrunning length', Buffer.from('99 a=b\n')],
  ['missing newline', Buffer.from('6 a=bX')],
  ['missing equals', Buffer.from('6 abcd\n')],
  ['empty key', Buffer.from('6 =abcd')],
  ['duplicate key', Buffer.concat([rawPaxRecord('a', '1'), rawPaxRecord('a', '2')])],
  ['forbidden key', rawPaxRecord('__proto__', 'x')],
  ['bad key character', rawPaxRecord('a b', 'x')]
];

for (const [name, payload] of malformedPaxPayloads) {
  test('malformed PAX payload rejected: ' + name, async () => {
    const report = await inspectTar(makeTar([{ name: 'px', typeflag: 'x', content: payload }, file('a', 'x')]));
    assert.equal(report.safe, false);
    assert.equal(report.findings[0].code, 'TARCAGE_PAX_FORMAT');
  });
}

test('multiple per-entry PAX headers before one entry are rejected', async () => {
  const report = await inspectTar(makeTar([paxEntry({ a: '1' }), paxEntry({ b: '2' }), file('a', 'x')]));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_PAX_FORMAT');
});

test('security-sensitive global PAX path is rejected', async () => {
  const report = await inspectTar(makeTar([{ name: 'pg', typeflag: 'g', content: paxPayload({ path: 'x' }) }, file('a', 'x')]));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_PAX_FORMAT');
});

test('duplicate global PAX keys across blocks are rejected', async () => {
  const global = { name: 'pg', typeflag: 'g', content: paxPayload({ comment: 'x' }) };
  const report = await inspectTar(makeTar([global, global, file('a', 'x')]));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_PAX_FORMAT');
});

test('harmless global PAX metadata is inherited', async () => {
  const global = { name: 'pg', typeflag: 'g', content: paxPayload({ comment: 'global' }) };
  const report = await inspectTar(makeTar([global, file('a', 'x')]));
  assert.equal(report.safe, true);
  assert.equal(report.entries[0].pax.comment, 'global');
});

test('local harmless PAX metadata overrides global metadata', async () => {
  const global = { name: 'pg', typeflag: 'g', content: paxPayload({ comment: 'global' }) };
  const report = await inspectTar(makeTar([global, paxEntry({ comment: 'local' }), file('a', 'x')]));
  assert.equal(report.safe, true);
  assert.equal(report.entries[0].pax.comment, 'local');
});

test('dangling PAX metadata without a following entry is rejected', async () => {
  const report = await inspectTar(makeTar([paxEntry({ comment: 'x' })]));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_MALFORMED_ARCHIVE');
});

test('GNU longname applies to the following entry', async () => {
  const longName = 'n'.repeat(120);
  const report = await inspectTar(makeTar([gnuMetadata('L', longName, { format: 'gnu' }), file('short', 'x', { format: 'gnu' })]));
  assert.equal(report.safe, true);
  assert.equal(report.entries[0].name, longName);
});

test('GNU longlink applies to the following symlink', async () => {
  const longTarget = 't'.repeat(120);
  const report = await inspectTar(makeTar([
    gnuMetadata('L', 'ln', { format: 'gnu' }),
    gnuMetadata('K', longTarget, { format: 'gnu' }),
    symlink('short', 'x', { format: 'gnu' })
  ]), { allowSymlinks: true });
  assert.equal(report.safe, true);
  assert.equal(report.entries[0].linkname, longTarget);
});

test('GNU longname and conflicting PAX path are rejected', async () => {
  const report = await inspectTar(makeTar([
    gnuMetadata('L', 'gnu-name'),
    paxEntry({ path: 'pax-name' }),
    file('x', '1')
  ]));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_PAX_CONFLICT');
});

test('matching GNU longname and PAX path are accepted', async () => {
  const report = await inspectTar(makeTar([
    gnuMetadata('L', 'same-name'),
    paxEntry({ path: 'same-name' }),
    file('same-name', '1')
  ]));
  assert.equal(report.safe, true);
});

for (const [name, payload] of [
  ['missing final NUL', Buffer.from('abc')],
  ['interior NUL', Buffer.from('a\0b\0')],
  ['empty payload', Buffer.alloc(0)]
]) {
  test('malformed GNU metadata rejected: ' + name, async () => {
    const report = await inspectTar(makeTar([{ name: 'g', typeflag: 'L', content: payload }, file('a', 'x')]));
    assert.equal(report.safe, false);
    assert.equal(report.findings[0].code, 'TARCAGE_GNU_METADATA');
  });
}

test('duplicate GNU longname blocks are rejected', async () => {
  const report = await inspectTar(makeTar([gnuMetadata('L', 'a'), gnuMetadata('L', 'b'), file('x', '1')]));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_GNU_METADATA');
});

test('duplicate GNU longlink blocks are rejected', async () => {
  const report = await inspectTar(makeTar([gnuMetadata('K', 'a'), gnuMetadata('K', 'b'), symlink('x', 'a')]), { allowSymlinks: true });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_GNU_METADATA');
});

test('dangling GNU metadata without a following entry is rejected', async () => {
  const report = await inspectTar(makeTar([gnuMetadata('L', 'long')]));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_MALFORMED_ARCHIVE');
});

test('metadata byte cap is enforced across blocks', async () => {
  const entries = [];
  for (let index = 0; index < 4; index += 1) {
    entries.push({ name: 'g' + index, typeflag: 'g', content: paxPayload({ ['comment' + index]: 'x'.repeat(40) }) });
  }
  entries.push(file('a', 'x'));
  const report = await inspectTar(makeTar(entries), { maxMetadataBytes: 100 });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_METADATA_LIMIT');
});

test('metadata entry count cap is enforced', async () => {
  const entries = [];
  for (let index = 0; index < 4; index += 1) {
    entries.push({ name: 'g' + index, typeflag: 'g', content: paxPayload({ ['k' + index]: 'v' }) });
  }
  entries.push(file('a', 'x'));
  const report = await inspectTar(makeTar(entries), { maxMetadataEntries: 2 });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_METADATA_LIMIT');
});

test('non-zero metadata padding is rejected', async () => {
  const report = await inspectTar(makeTar([paxEntry({ comment: 'x' }, { paddingByte: 1 }), file('a', 'x')]));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_PADDING_CORRUPT');
});

test('ustar size in a non-file hardlink must be zero', async () => {
  const report = await inspectTar(makeTar([hardlink('h', 'a', { size: 1, content: 'x' })]), { allowHardlinks: true });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_MALFORMED_ARCHIVE');
});

test('non-link entry carrying a link target is malformed', async () => {
  const report = await inspectTar(makeTar([file('a', 'x', { linkname: 'target' })]));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_MALFORMED_ARCHIVE');
});

test('ustar magic with a malformed version is rejected', async () => {
  const report = await inspectTar(archiveWithFirstHeaderPatch(263, 'X0'));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_MALFORMED_ARCHIVE');
});

test('GNU magic with a malformed version is rejected', async () => {
  const archive = patchFirstHeader(makeTar([file('a', 'x', { format: 'gnu' })]), 264, 'X');
  const report = await inspectTar(archive);
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_MALFORMED_ARCHIVE');
});

for (const [field, offset, text] of [
  ['mode', 100, '00000644'],
  ['size', 124, '000000000001']
]) {
  test('unterminated numeric field rejected for ' + field, async () => {
    const report = await inspectTar(archiveWithFirstHeaderPatch(offset, text));
    assert.equal(report.safe, false);
    assert.equal(report.findings[0].code, 'TARCAGE_NUMERIC_FIELD');
  });
}

for (const key of ['GNU.sparse', 'GNU.sparse.map', 'GNU.dumpdir', 'SCHILY.filetype']) {
  test('unsupported semantic PAX extension rejected: ' + key, async () => {
    const report = await inspectTar(makeTar([paxEntry({ [key]: key === 'SCHILY.filetype' ? 'regular' : '1' }), file('a', 'x')]));
    assert.equal(report.safe, false);
    assert.equal(report.findings[0].code, 'TARCAGE_UNSUPPORTED_EXTENSION');
  });
}

test('unsupported semantic global PAX extension is rejected before later entries', async () => {
  const report = await inspectTar(makeTar([
    { name: 'pg', typeflag: 'g', content: paxPayload({ 'GNU.sparse.realsize': '99' }) },
    file('a', 'x')
  ]));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_UNSUPPORTED_EXTENSION');
});

test('GNU sparse typeflag is rejected explicitly', async () => {
  const report = await inspectTar(makeTar([{ name: 'sparse', typeflag: 'S', content: '', size: 0 }]));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_UNSUPPORTED_TYPEFLAG');
});
