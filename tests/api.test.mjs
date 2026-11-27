import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  TARCAGE_VERSION,
  TarCageError,
  TarChecksumError,
  TarExtractionError,
  TarFormatError,
  TarInputError,
  TarLimitError,
  TarLinkError,
  TarPathError,
  TarPolicyError,
  auditTar,
  createTarPolicy,
  inspectTar,
  listTarEntries,
  parseTar,
  validateTarPath
} from '../src/index.mjs';
import { directory, expectTarError, file, findingCodes, gzip, makeTar, paxEntry } from './helpers.mjs';

const simpleEntries = [directory('docs/'), file('docs/readme.txt', 'hello world')];
const simpleTar = makeTar(simpleEntries);

test('package version is 1.0.0', () => {
  assert.equal(TARCAGE_VERSION, '1.0.0');
});

for (const [name, value] of [
  ['inspectTar', inspectTar],
  ['auditTar', auditTar],
  ['parseTar', parseTar],
  ['listTarEntries', listTarEntries],
  ['validateTarPath', validateTarPath],
  ['createTarPolicy', createTarPolicy]
]) {
  test(name + ' is exported as a function', () => {
    assert.equal(typeof value, 'function');
  });
}

for (const [name, type] of [
  ['TarCageError', TarCageError],
  ['TarInputError', TarInputError],
  ['TarPolicyError', TarPolicyError],
  ['TarFormatError', TarFormatError],
  ['TarChecksumError', TarChecksumError],
  ['TarPathError', TarPathError],
  ['TarLinkError', TarLinkError],
  ['TarLimitError', TarLimitError],
  ['TarExtractionError', TarExtractionError]
]) {
  test(name + ' participates in the typed error hierarchy', () => {
    const error = new type('TARCAGE_TEST', 'typed failure');
    assert.ok(error instanceof TarCageError);
    assert.equal(error.code, 'TARCAGE_TEST');
    assert.equal(error.reason, 'typed failure');
  });
}

test('inspectTar parses a simple ustar archive from a Buffer', async () => {
  const report = await inspectTar(simpleTar);
  assert.equal(report.safe, true);
  assert.equal(report.format, 'ustar');
  assert.equal(report.compressed, false);
  assert.equal(report.stats.entries, 2);
  assert.equal(report.stats.files, 1);
  assert.equal(report.stats.directories, 1);
  assert.equal(report.stats.totalEntryBytes, 11);
});

test('inspectTar parses a simple archive from a Uint8Array view', async () => {
  const backing = new Uint8Array(simpleTar.length + 11);
  backing.set(simpleTar, 7);
  const view = backing.subarray(7, 7 + simpleTar.length);
  const report = await inspectTar(view);
  assert.equal(report.safe, true);
  assert.equal(report.entries[1].name, 'docs/readme.txt');
});

test('inspectTar parses an archive from a file path', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'tarcage-api-'));
  try {
    const archive = path.join(dir, 'input.tar');
    await writeFile(archive, simpleTar);
    const report = await inspectTar(archive);
    assert.equal(report.safe, true);
    assert.equal(report.stats.uncompressedBytes, simpleTar.length);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('inspectTar auto-detects gzip data', async () => {
  const report = await inspectTar(gzip(simpleTar));
  assert.equal(report.safe, true);
  assert.equal(report.compressed, true);
  assert.equal(report.stats.entries, 2);
  assert.equal(report.stats.compressionRatio > 0, true);
});

test('gzip and plain input produce the same uncompressed digest', async () => {
  const plain = await inspectTar(simpleTar);
  const compressed = await inspectTar(gzip(simpleTar));
  assert.equal(compressed.stats.uncompressedSha256, plain.stats.uncompressedSha256);
});

test('compressed false treats gzip bytes as plain tar input', async () => {
  const report = await inspectTar(gzip(simpleTar), { compressed: false });
  assert.equal(report.safe, false);
});

test('compressed true rejects non-gzip data as a gzip stream', async () => {
  const report = await inspectTar(simpleTar, { compressed: true });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_GZIP_ERROR');
});

test('parseTar returns strict parse output with entries and stats', async () => {
  const result = await parseTar(simpleTar);
  assert.equal(result.entries.length, 2);
  assert.equal(result.stats.uncompressedSha256.length, 64);
  assert.equal(result.findings.length, 0);
});

test('listTarEntries returns only entry metadata', async () => {
  const entries = await listTarEntries(simpleTar);
  assert.equal(Array.isArray(entries), true);
  assert.equal(entries.map((entry) => entry.name).join(','), 'docs,docs/readme.txt');
});

test('entry metadata does not expose file contents', async () => {
  const [entry] = await listTarEntries(makeTar([file('secret.txt', 'do not retain')]));
  assert.equal('content' in entry, false);
  assert.equal('data' in entry, false);
});

test('inspectTar converts archive violations into a fatal finding', async () => {
  const report = await inspectTar(makeTar([file('../evil', 'x')]));
  assert.equal(report.safe, false);
  assert.equal(report.findings.at(-1).severity, 'fatal');
  assert.equal(report.findings.at(-1).code, 'TARCAGE_PATH_TRAVERSAL');
});

test('parseTar throws the same violation as a typed error', async () => {
  await expectTarError(parseTar(makeTar([file('../evil', 'x')])), 'TARCAGE_PATH_TRAVERSAL');
});

test('auditTar includes verdict, policy, and recommendations', async () => {
  const report = await auditTar(simpleTar, { maxEntries: 10 });
  assert.equal(report.verdict, 'safe');
  assert.equal(report.policy.maxEntries, 10);
  assert.equal(Array.isArray(report.recommendations), true);
});

test('auditTar reports unsafe verdicts without throwing', async () => {
  const report = await auditTar(makeTar([file('/absolute', 'x')]));
  assert.equal(report.verdict, 'unsafe');
  assert.equal(report.recommendations[0].includes('Do not extract'), true);
});

test('empty archive with two zero end blocks is valid', async () => {
  const report = await inspectTar(Buffer.alloc(1024));
  assert.equal(report.safe, true);
  assert.equal(report.stats.entries, 0);
  assert.equal(report.stats.endMarkers >= 2, true);
});

test('empty input is not a valid tar archive', async () => {
  const report = await inspectTar(Buffer.alloc(0));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_EOF_MISSING');
});

test('ustar prefix field is joined with the name field', async () => {
  const archive = makeTar([file('file.txt', 'x', { prefix: 'prefix-dir' })]);
  const entries = await listTarEntries(archive);
  assert.equal(entries[0].name, 'prefix-dir/file.txt');
});

test('v7 header without ustar magic is accepted', async () => {
  const report = await inspectTar(makeTar([file('old.txt', 'x', { format: 'v7' })]));
  assert.equal(report.safe, true);
  assert.equal(report.format, 'v7');
});

test('GNU magic header is recognized', async () => {
  const report = await inspectTar(makeTar([file('gnu.txt', 'x', { format: 'gnu' })]));
  assert.equal(report.safe, true);
  assert.equal(report.format, 'gnu');
});

test('pax format takes precedence in report format', async () => {
  const report = await inspectTar(makeTar([paxEntry({ comment: 'yes' }), file('a.txt', 'x')]));
  assert.equal(report.safe, true);
  assert.equal(report.format, 'pax');
});

test('entry indexes are stable archive order positions', async () => {
  const entries = await listTarEntries(makeTar([file('a', '1'), file('b', '2'), file('c', '3')]));
  assert.deepEqual(entries.map((entry) => entry.index), [0, 1, 2]);
});

test('entry offsets are 512-byte aligned', async () => {
  const entries = await listTarEntries(makeTar([file('a', '1'), file('b', '2')]));
  for (const entry of entries) assert.equal(entry.offset % 512, 0);
});

test('mode is sanitized while rawMode remains visible', async () => {
  const [entry] = await listTarEntries(makeTar([file('run', 'x', { mode: 0o4755 })]));
  assert.equal(entry.rawMode, 0o4755);
  assert.equal(entry.mode & 0o4000, 0);
});

test('setuid stripping creates a warning but not a fatal inspection failure', async () => {
  const report = await inspectTar(makeTar([file('run', 'x', { mode: 0o4755 })]));
  assert.equal(report.safe, true);
  assert.deepEqual(findingCodes(report), ['TARCAGE_MODE_STRIPPED']);
});

test('createTarPolicy freezes the reusable object', () => {
  const policy = createTarPolicy({ maxEntries: 3 });
  assert.equal(Object.isFrozen(policy), true);
  assert.equal(policy.maxEntries, 3);
});

test('createTarPolicy accepts a policy object as reusable input', () => {
  const first = createTarPolicy({ maxEntries: 3 });
  const second = createTarPolicy(first);
  assert.equal(second.maxEntries, 3);
});

const invalidOptions = [
  ['unknownOption', true],
  ['maxEntries', 0],
  ['maxEntries', 1.5],
  ['maxUncompressedBytes', -1],
  ['maxCompressionRatio', 0],
  ['maxCompressionRatio', Number.POSITIVE_INFINITY],
  ['maxDepth', '4'],
  ['umask', -1],
  ['umask', 0o1000],
  ['allowSymlinks', 1],
  ['compressed', 'yes'],
  ['stripComponents', -1],
  ['maxMetadataEntries', 0],
  ['rejectDuplicates', 'true']
];

for (const [key, value] of invalidOptions) {
  test('policy rejects invalid option ' + key + ' value ' + String(value), () => {
    assert.throws(() => createTarPolicy({ [key]: value }), (error) => error.code === 'TARCAGE_INVALID_OPTIONS');
  });
}

for (const key of [
  'strictEof',
  'strictChecksum',
  'strictPadding',
  'allowSignedChecksums',
  'allowSymlinks',
  'allowHardlinks',
  'allowSpecialFiles',
  'allowContiguousFiles',
  'allowSpecialModes',
  'rejectDuplicates',
  'rejectCaseCollisions',
  'dryRun'
]) {
  test('default boolean policy ' + key + ' is explicit', () => {
    assert.equal(typeof createTarPolicy()[key], 'boolean');
  });
}

test('validateTarPath returns a structured non-throwing result', () => {
  const result = validateTarPath('../evil');
  assert.equal(result.valid, false);
  assert.equal(result.normalized, null);
  assert.equal(result.findings[0].code, 'TARCAGE_PATH_TRAVERSAL');
});

test('validateTarPath normalizes dot segments', () => {
  const result = validateTarPath('./a/./b.txt');
  assert.equal(result.valid, true);
  assert.equal(result.normalized, 'a/b.txt');
  assert.equal(result.depth, 2);
});

for (const input of [null, undefined, 42, {}, []]) {
  test('inspectTar rejects invalid input type ' + String(input), async () => {
    await assert.rejects(inspectTar(input), (error) => error instanceof TarInputError && error.code === 'TARCAGE_INVALID_INPUT');
  });
}

test('inspectTar path input failure throws input error instead of an unsafe report', async () => {
  await assert.rejects(inspectTar(path.join(os.tmpdir(), 'definitely-not-present-tarcage.tar')), (error) => {
    assert.equal(error.code, 'TARCAGE_INPUT_IO');
    return true;
  });
});

test('error serialization exposes stable fields', () => {
  const error = new TarFormatError('TARCAGE_MALFORMED_ARCHIVE', 'bad archive', { path: 'x' });
  const json = error.toJSON();
  assert.equal(json.code, 'TARCAGE_MALFORMED_ARCHIVE');
  assert.equal(json.reason, 'bad archive');
  assert.deepEqual(json.details, { path: 'x' });
});

test('stats count entry categories independently', async () => {
  const report = await inspectTar(makeTar([
    directory('d/'),
    file('d/f', 'x'),
    { name: 'd/c', typeflag: '3', content: '', size: 0 },
    { name: 'd/p', typeflag: '6', content: '', size: 0 }
  ]), { allowSpecialFiles: true });
  assert.equal(report.stats.files, 1);
  assert.equal(report.stats.directories, 1);
  assert.equal(report.stats.special, 2);
});

test('multiple small entries can be parsed in order', async () => {
  const entries = [];
  for (let index = 0; index < 20; index += 1) entries.push(file('f' + index, String(index)));
  const parsed = await listTarEntries(makeTar(entries));
  assert.equal(parsed.length, 20);
  assert.equal(parsed[19].name, 'f19');
});

test('root directory entries are accepted as directories', async () => {
  const report = await inspectTar(makeTar([directory('./'), file('a', 'x')]));
  assert.equal(report.safe, true);
  assert.equal(report.entries[0].name, '.');
});

test('root path is rejected for regular files', async () => {
  const report = await inspectTar(makeTar([file('./', 'x')]));
  assert.equal(report.safe, false);
});
