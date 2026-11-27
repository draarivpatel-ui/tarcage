import test from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import { auditTar, inspectTar } from '../src/index.mjs';
import { directory, file, gzip, hardlink, makeTar, symlink } from './helpers.mjs';

function entriesOfType(typeflag, extra = {}) {
  return [{ name: 'entry', typeflag, content: '', size: 0, ...extra }];
}

test('streaming gzip bomb is aborted by ratio before full expansion', async () => {
  const expanded = Buffer.alloc(12 * 1024 * 1024, 0);
  const bomb = gzip(expanded);
  const started = Date.now();
  const report = await inspectTar(bomb, {
    maxCompressionRatio: 100,
    maxUncompressedBytes: 256 * 1024 * 1024
  });
  const elapsed = Date.now() - started;
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_RATIO_LIMIT');
  assert.equal(report.stats.uncompressedBytes < expanded.length, true);
  assert.equal(elapsed < 5000, true);
});

test('gzip bomb can also be stopped by uncompressed byte cap', async () => {
  const bomb = gzip(Buffer.alloc(4 * 1024 * 1024, 0));
  const report = await inspectTar(bomb, {
    maxCompressionRatio: 1000000,
    maxUncompressedBytes: 1024 * 1024
  });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_UNCOMPRESSED_LIMIT');
});

test('compressed input cap rejects large gzip containers before full read', async () => {
  const archive = gzip(makeTar([file('a', 'x')]));
  const report = await inspectTar(archive, { maxCompressedBytes: archive.length - 1 });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_COMPRESSED_LIMIT');
});

test('compressed input cap applies to uncompressed input too', async () => {
  const archive = makeTar([file('a', 'x')]);
  const report = await inspectTar(archive, { maxCompressedBytes: archive.length - 1, compressed: false });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_COMPRESSED_LIMIT');
});

test('uncompressed cap applies to plain tar bytes', async () => {
  const archive = makeTar([file('a', 'x')]);
  const report = await inspectTar(archive, { maxUncompressedBytes: archive.length - 1 });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_UNCOMPRESSED_LIMIT');
});

test('valid archive just below uncompressed cap is accepted', async () => {
  const archive = makeTar([file('a', 'x')]);
  const report = await inspectTar(archive, { maxUncompressedBytes: archive.length });
  assert.equal(report.safe, true);
});

for (const size of [1, 16, 1024]) {
  test('entry byte cap boundary accepts size ' + size, async () => {
    const report = await inspectTar(makeTar([file('a', Buffer.alloc(size, 65))]), { maxEntryBytes: size });
    assert.equal(report.safe, true);
  });

  test('entry byte cap rejects size ' + (size + 1), async () => {
    const report = await inspectTar(makeTar([file('a', Buffer.alloc(size + 1, 65))]), { maxEntryBytes: size });
    assert.equal(report.safe, false);
    assert.equal(report.findings[0].code, 'TARCAGE_ENTRY_SIZE_LIMIT');
  });
}

for (const count of [1, 2, 8]) {
  test('maxEntries boundary accepts exactly ' + count, async () => {
    const entries = [];
    for (let index = 0; index < count; index += 1) entries.push(file('f' + index, 'x'));
    const report = await inspectTar(makeTar(entries), { maxEntries: count });
    assert.equal(report.safe, true);
  });

  test('maxEntries rejects count plus one for cap ' + count, async () => {
    const entries = [];
    for (let index = 0; index < count + 1; index += 1) entries.push(file('f' + index, 'x'));
    const report = await inspectTar(makeTar(entries), { maxEntries: count });
    assert.equal(report.safe, false);
    assert.equal(report.findings[0].code, 'TARCAGE_ENTRY_LIMIT');
  });
}

test('many small zero-length entries are bounded by maxEntries', async () => {
  const entries = [];
  for (let index = 0; index < 40; index += 1) entries.push(file('f' + index, ''));
  const report = await inspectTar(makeTar(entries), { maxEntries: 10 });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_ENTRY_LIMIT');
});

test('archive depth cap is enforced during parsing', async () => {
  const report = await inspectTar(makeTar([file('a/b/c', 'x')]), { maxDepth: 2 });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_PATH_TOO_DEEP');
});

test('archive path byte cap is enforced during parsing', async () => {
  const report = await inspectTar(makeTar([file('abcdefghij', 'x')]), { maxPathLength: 5 });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_PATH_TOO_LONG');
});

test('archive component byte cap is enforced during parsing', async () => {
  const report = await inspectTar(makeTar([file('abcdefghij', 'x')]), { maxComponentLength: 5 });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_COMPONENT_TOO_LONG');
});

const typeCases = [
  ['\0', true, {}, 'file'],
  ['0', true, {}, 'file'],
  ['1', false, {}, null],
  ['2', false, {}, null],
  ['3', false, {}, null],
  ['4', false, {}, null],
  ['5', true, {}, 'directory'],
  ['6', false, {}, null],
  ['7', false, {}, null],
  ['A', false, {}, null],
  ['D', false, {}, null],
  ['S', false, {}, null],
  ['V', false, {}, null],
  ['X', false, {}, null],
  ['?', false, {}, null]
];

for (const [typeflag, expectedSafe, extraOptions, expectedType] of typeCases) {
  test('typeflag ' + JSON.stringify(typeflag) + ' default policy safety is ' + expectedSafe, async () => {
    const input = typeflag === '1'
      ? hardlink('entry', 'target')
      : typeflag === '2'
        ? symlink('entry', 'target')
        : entriesOfType(typeflag)[0];
    const report = await inspectTar(makeTar([input]), extraOptions);
    assert.equal(report.safe, expectedSafe);
    if (expectedSafe) assert.equal(report.entries[0].type, expectedType);
  });
}

test('contiguous file can be inspected only after explicit opt-in', async () => {
  const report = await inspectTar(makeTar([{ name: 'c', typeflag: '7', content: 'x', size: 1 }]), { allowContiguousFiles: true });
  assert.equal(report.safe, true);
  assert.equal(report.entries[0].type, 'file');
  assert.equal(report.entries[0].contiguous, true);
});

for (const typeflag of ['3', '4', '6']) {
  test('special typeflag ' + typeflag + ' can be inspected after explicit opt-in', async () => {
    const report = await inspectTar(makeTar(entriesOfType(typeflag)), { allowSpecialFiles: true });
    assert.equal(report.safe, true);
    assert.equal(report.stats.special, 1);
  });

  test('special typeflag ' + typeflag + ' with nonzero size is malformed', async () => {
    const report = await inspectTar(makeTar(entriesOfType(typeflag, { size: 1, content: 'x' })), { allowSpecialFiles: true });
    assert.equal(report.safe, false);
    assert.equal(report.findings[0].code, 'TARCAGE_MALFORMED_ARCHIVE');
  });
}

test('unknown high-byte typeflag is rejected', async () => {
  const archive = Buffer.from(makeTar([file('a', 'x')]));
  archive[156] = 0xff;
  let sum = 0;
  archive.fill(0x20, 148, 156);
  for (const byte of archive.subarray(0, 512)) sum += byte;
  const text = sum.toString(8).padStart(6, '0');
  archive.write(text, 148, 'ascii');
  archive[154] = 0x20;
  const report = await inspectTar(archive);
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_UNSUPPORTED_TYPEFLAG');
});

for (const bits of [0o4000, 0o2000, 0o1000, 0o7000]) {
  test('special mode bits ' + bits.toString(8) + ' are stripped with warning', async () => {
    const report = await inspectTar(makeTar([file('x', '1', { mode: bits | 0o755 })]));
    assert.equal(report.safe, true);
    assert.equal(report.entries[0].mode & bits, 0);
    assert.equal(report.findings[0].code, 'TARCAGE_MODE_STRIPPED');
  });

  test('special mode bits ' + bits.toString(8) + ' can be preserved only by opt-in', async () => {
    const report = await inspectTar(makeTar([file('x', '1', { mode: bits | 0o755 })]), { allowSpecialModes: true, umask: 0 });
    assert.equal(report.safe, true);
    assert.equal(report.entries[0].mode & bits, bits);
  });
}

test('duplicate file entries are rejected even with different contents', async () => {
  const report = await inspectTar(makeTar([file('same', 'one'), file('same', 'two')]));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_DUPLICATE_PATH');
});

test('file then child overlap is rejected', async () => {
  const report = await inspectTar(makeTar([file('a', 'x'), file('a/child', 'x')]));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_OVERLAPPING_ENTRIES');
});

test('symlink then child overlap is rejected', async () => {
  const report = await inspectTar(makeTar([symlink('a', 'target'), file('a/child', 'x')]), { allowSymlinks: true });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_OVERLAPPING_ENTRIES');
});

test('hardlink then child overlap is rejected', async () => {
  const report = await inspectTar(makeTar([file('target', 'x'), hardlink('a', 'target'), file('a/child', 'x')]), { allowHardlinks: true });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_OVERLAPPING_ENTRIES');
});

test('truncated gzip stream is rejected as gzip error', async () => {
  const compressed = gzip(makeTar([file('a', 'x')]));
  const report = await inspectTar(compressed.subarray(0, compressed.length - 5));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_GZIP_ERROR');
});

test('gzip trailing garbage is rejected', async () => {
  const compressed = Buffer.concat([gzip(makeTar([file('a', 'x')])), Buffer.from('junk')]);
  const report = await inspectTar(compressed);
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_GZIP_ERROR');
});

test('concatenated gzip members are decompressed in sequence and still tar-validated', async () => {
  const one = gzip(makeTar([file('a', 'x')], { endBlocks: 0 }));
  const two = gzip(Buffer.alloc(1024, 0));
  const report = await inspectTar(Buffer.concat([one, two]));
  assert.equal(report.safe, true);
});

test('gzip header-only input produces a tar end-of-file failure', async () => {
  const report = await inspectTar(zlib.gzipSync(Buffer.alloc(0)));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_EOF_MISSING');
});

test('zero-filled tar input larger than cap is limited before full logical parsing', async () => {
  const report = await inspectTar(Buffer.alloc(1024 * 1024), { compressed: false, maxUncompressedBytes: 1000 });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_UNCOMPRESSED_LIMIT');
});

test('compression ratio sample allows small normal gzip archives', async () => {
  const report = await inspectTar(gzip(makeTar([file('a', 'x')])), { maxCompressionRatio: 2 });
  assert.equal(report.safe, true);
});

test('compression ratio sample catches sustained expansion when enabled strictly', async () => {
  const zeros = Buffer.alloc(2 * 1024 * 1024, 0);
  const report = await inspectTar(gzip(zeros), { maxCompressionRatio: 2, maxUncompressedBytes: 10 * 1024 * 1024 });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_RATIO_LIMIT');
});

test('audit recommendations mention special entries when explicitly inspected', async () => {
  const report = await auditTar(makeTar(entriesOfType('6')), { allowSpecialFiles: true });
  assert.equal(report.safe, true);
  assert.equal(report.recommendations.some((line) => line.includes('Special filesystem entries')), true);
});

const traversalPayloads = [
  '../evil',
  'safe/../../evil',
  '/tmp/evil',
  'C:/evil',
  '\\\\server\\share',
  'a\\..\\evil',
  'evil\0name',
  'evil\u202ename',
  'NUL',
  'CON.txt',
  'evil.',
  'evil '
];

for (const payload of traversalPayloads) {
  test('tar-slip payload rejected in archive: ' + JSON.stringify(payload), async () => {
    const report = await inspectTar(makeTar([file(payload, 'x')]));
    assert.equal(report.safe, false);
  });
}

for (const payload of ['../evil', '/etc/passwd', 'C:/evil', 'a\\evil']) {
  test('symlink escape payload rejected in archive: ' + payload, async () => {
    const report = await inspectTar(makeTar([symlink('ln', payload)]), { allowSymlinks: true });
    assert.equal(report.safe, false);
  });

  test('hardlink escape payload rejected in archive: ' + payload, async () => {
    const report = await inspectTar(makeTar([hardlink('ln', payload)]), { allowHardlinks: true });
    assert.equal(report.safe, false);
  });
}

test('resource limit errors expose typed stable codes', async () => {
  const report = await inspectTar(makeTar([file('a', 'x')]), { maxEntries: 0 }).catch((error) => error);
  assert.equal(report.code, 'TARCAGE_INVALID_OPTIONS');
});

for (const count of [1, 2, 3]) {
  test('duplicate directory behavior remains strict at count ' + count, async () => {
    const entries = [];
    for (let index = 0; index < count; index += 1) entries.push(directory('d/'));
    const report = await inspectTar(makeTar(entries));
    assert.equal(report.safe, count === 1);
  });
}

test('overlapping device and child entry is rejected when special files are allowed', async () => {
  const report = await inspectTar(makeTar([
    { name: 'dev', typeflag: '4', content: '', size: 0 },
    file('dev/child', 'x')
  ]), { allowSpecialFiles: true });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_OVERLAPPING_ENTRIES');
});
