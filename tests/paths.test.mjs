import test from 'node:test';
import assert from 'node:assert/strict';
import { collisionKey, validateTarPath, inspectTar } from '../src/index.mjs';
import { directory, file, makeTar, symlink } from './helpers.mjs';

const validPaths = [
  'a',
  'a/b/c',
  './a',
  'a/./b',
  'dir/',
  'file name.txt',
  '.well-known/file',
  'caf\u00e9/file.txt',
  '\u65e5\u672c\u8a9e/\u6587\u4ef6.txt',
  'x'.repeat(255),
  'a/' + 'b/'.repeat(30) + 'c',
  '.'
];

for (const value of validPaths) {
  test('valid archive path accepted: ' + JSON.stringify(value.slice(0, 40)), () => {
    const result = validateTarPath(value);
    assert.equal(result.valid, true, JSON.stringify(result.findings));
    assert.notEqual(result.normalized, null);
  });
}

test('dot segments are removed during normalization', () => {
  const result = validateTarPath('./a/./b/./c.txt');
  assert.equal(result.normalized, 'a/b/c.txt');
});

test('trailing slash is reported separately', () => {
  const result = validateTarPath('dir/sub/');
  assert.equal(result.valid, true);
  assert.equal(result.normalized, 'dir/sub');
  assert.equal(result.hadTrailingSlash, true);
});

test('root dot path has zero depth', () => {
  const result = validateTarPath('./');
  assert.equal(result.valid, true);
  assert.equal(result.normalized, '.');
  assert.equal(result.depth, 0);
});

const invalidPathCases = [
  ['empty string', '', 'TARCAGE_PATH_EMPTY'],
  ['posix root', '/', 'TARCAGE_ABSOLUTE_PATH'],
  ['absolute posix file', '/tmp/evil', 'TARCAGE_ABSOLUTE_PATH'],
  ['double slash server path', '//server/share', 'TARCAGE_UNC_PATH'],
  ['backslash root', '\\evil', 'TARCAGE_ABSOLUTE_PATH'],
  ['unc backslashes', '\\\\server\\share', 'TARCAGE_UNC_PATH'],
  ['drive relative', 'C:evil', 'TARCAGE_DRIVE_PATH'],
  ['drive absolute', 'C:/evil', 'TARCAGE_DRIVE_PATH'],
  ['drive backslash', 'c:\\evil', 'TARCAGE_DRIVE_PATH'],
  ['parent only', '..', 'TARCAGE_PATH_TRAVERSAL'],
  ['parent prefix', '../evil', 'TARCAGE_PATH_TRAVERSAL'],
  ['nested parent', 'a/../evil', 'TARCAGE_PATH_TRAVERSAL'],
  ['terminal parent', 'a/..', 'TARCAGE_PATH_TRAVERSAL'],
  ['many parent segments', 'a/../../evil', 'TARCAGE_PATH_TRAVERSAL'],
  ['backslash separator', 'a\\evil', 'TARCAGE_BACKSLASH_SEPARATOR'],
  ['mixed separator', 'a/b\\evil', 'TARCAGE_BACKSLASH_SEPARATOR'],
  ['empty interior segment', 'a//evil', 'TARCAGE_EMPTY_PATH_SEGMENT'],
  ['many empty segments', 'a///evil', 'TARCAGE_EMPTY_PATH_SEGMENT'],
  ['trailing component dot', 'evil./file', 'TARCAGE_TRAILING_DOT_OR_SPACE'],
  ['trailing component space', 'evil /file', 'TARCAGE_TRAILING_DOT_OR_SPACE'],
  ['final trailing dot', 'evil.', 'TARCAGE_TRAILING_DOT_OR_SPACE'],
  ['final trailing space', 'evil ', 'TARCAGE_TRAILING_DOT_OR_SPACE']
];

for (const [name, value, code] of invalidPathCases) {
  test('invalid archive path rejected: ' + name, () => {
    const result = validateTarPath(value);
    assert.equal(result.valid, false);
    assert.equal(result.findings[0].code, code);
  });
}

for (const drive of ['A:', 'c:', 'Z:']) {
  test('drive prefix rejected case ' + drive, () => {
    assert.equal(validateTarPath(drive + '/x').valid, false);
  });
}

const reserved = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM9', 'LPT1', 'LPT2', 'LPT9'];
for (const name of reserved) {
  test('Windows reserved device name rejected: ' + name, () => {
    assert.equal(validateTarPath('dir/' + name).valid, false);
  });
  test('Windows reserved device name with extension rejected: ' + name, () => {
    const result = validateTarPath('dir/' + name.toLowerCase() + '.txt');
    assert.equal(result.valid, false);
    assert.equal(result.findings[0].code, 'TARCAGE_RESERVED_NAME');
  });
}

for (const name of ['CONSOLE', 'com0', 'lpt10', 'null', 'auxiliary']) {
  test('non-reserved similar name accepted: ' + name, () => {
    assert.equal(validateTarPath('dir/' + name).valid, true);
  });
}

const controlCases = [
  ['NUL', 0x00],
  ['bell', 0x07],
  ['newline', 0x0a],
  ['carriage return', 0x0d],
  ['unit separator', 0x1f],
  ['delete', 0x7f],
  ['C1 control', 0x85],
  ['zero width space', 0x200b],
  ['left to right mark', 0x200e],
  ['right to left embedding', 0x202b],
  ['right to left override', 0x202e],
  ['word joiner', 0x2060],
  ['isolate pop', 0x2069],
  ['byte order mark', 0xfeff],
  ['interlinear annotation', 0xfff9]
];

for (const [name, codePoint] of controlCases) {
  test('control or invisible character rejected: ' + name, () => {
    const value = 'safe' + String.fromCodePoint(codePoint) + 'evil';
    const result = validateTarPath(value);
    assert.equal(result.valid, false);
    assert.equal(result.findings[0].code, 'TARCAGE_CONTROL_CHARACTER');
  });
}

test('unicode tag control character is rejected', () => {
  const value = 'safe' + String.fromCodePoint(0xe0001) + 'evil';
  assert.equal(validateTarPath(value).valid, false);
});

test('maximum path byte length is enforced in bytes', () => {
  const value = '\u00e9'.repeat(41);
  const result = validateTarPath(value, { maxPathLength: 80 });
  assert.equal(result.valid, false);
  assert.equal(result.findings[0].code, 'TARCAGE_PATH_TOO_LONG');
});

test('maximum component byte length is enforced in bytes', () => {
  const value = '\u00e9'.repeat(21);
  const result = validateTarPath(value, { maxComponentLength: 40 });
  assert.equal(result.valid, false);
  assert.equal(result.findings[0].code, 'TARCAGE_COMPONENT_TOO_LONG');
});

for (const [pathLength, componentLength] of [[10, 10], [10, 9], [255, 255]]) {
  test('boundary component length accepted for ' + componentLength, () => {
    assert.equal(validateTarPath('x'.repeat(componentLength), { maxComponentLength: componentLength }).valid, true);
  });
}

test('maximum depth is enforced', () => {
  const result = validateTarPath('a/b/c/d', { maxDepth: 3 });
  assert.equal(result.valid, false);
  assert.equal(result.findings[0].code, 'TARCAGE_PATH_TOO_DEEP');
});

for (const depth of [1, 2, 8, 32]) {
  test('depth boundary accepted for ' + depth, () => {
    const value = Array.from({ length: depth }, (_, index) => 'd' + index).join('/');
    const result = validateTarPath(value, { maxDepth: depth });
    assert.equal(result.valid, true);
    assert.equal(result.depth, depth);
  });
}

test('multiple independent path findings can be reported together', () => {
  const result = validateTarPath('C:/a\\../evil.');
  assert.equal(result.valid, false);
  assert.equal(result.findings.length > 1, true);
});

test('collision key folds case and compatibility normalization', () => {
  assert.equal(collisionKey('A\u00e9'), collisionKey('a\u0065\u0301'));
});

test('archive duplicate exact paths are rejected', async () => {
  const report = await inspectTar(makeTar([file('same', '1'), file('same', '2')]));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_DUPLICATE_PATH');
});

test('normalized dot-segment duplicates are rejected', async () => {
  const report = await inspectTar(makeTar([file('a', '1'), file('./a', '2')]));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_DUPLICATE_PATH');
});

test('duplicate directories are rejected by default', async () => {
  const report = await inspectTar(makeTar([directory('d/'), directory('./d/')]));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_DUPLICATE_PATH');
});

test('duplicate directories can be tolerated only when explicitly configured', async () => {
  const report = await inspectTar(makeTar([directory('d/'), directory('./d/')]), { rejectDuplicates: false });
  assert.equal(report.safe, true);
});

for (const [left, right] of [
  ['A', 'a'],
  ['Dir/file.txt', 'dir/other.txt'],
  ['caf\u00e9', 'caf\u0065\u0301'],
  ['xo/Child', 'XO/child']
]) {
  test('case or normalization collision rejected for ' + left + ' and ' + right, async () => {
    const report = await inspectTar(makeTar([file(left, '1'), file(right, '2')]));
    assert.equal(report.safe, false);
    assert.equal(report.findings[0].code, 'TARCAGE_CASE_COLLISION');
  });
}

test('case collision check can be disabled for Linux-only consumers', async () => {
  const report = await inspectTar(makeTar([file('A', '1'), file('a', '2')]), { rejectCaseCollisions: false });
  assert.equal(report.safe, true);
});

for (const [first, second] of [
  ['a', 'a/b'],
  ['a/b', 'a'],
  ['link', 'link/child'],
  ['dir/file', 'dir']
]) {
  test('overlapping entries rejected for ' + first + ' then ' + second, async () => {
    const entries = first.endsWith('file') || !first.includes('/') || first === 'link' || first === 'a'
      ? [file(first, '1'), file(second, '2')]
      : [file(first, '1'), file(second, '2')];
    const report = await inspectTar(makeTar(entries));
    assert.equal(report.safe, false);
    assert.equal(report.findings[0].code, 'TARCAGE_OVERLAPPING_ENTRIES');
  });
}

test('implicit parent directories may be explicitly declared later', async () => {
  const report = await inspectTar(makeTar([file('d/f', 'x'), directory('d/')]));
  assert.equal(report.safe, true);
});

test('directory then child is a normal valid layout', async () => {
  const report = await inspectTar(makeTar([directory('d/'), file('d/f', 'x')]));
  assert.equal(report.safe, true);
});

test('trailing slash on a regular file is malformed', async () => {
  const report = await inspectTar(makeTar([file('a/', 'x')]));
  assert.equal(report.safe, false);
});

test('trailing slash on a symlink is malformed', async () => {
  const report = await inspectTar(makeTar([symlink('a/', 'target')]), { allowSymlinks: true });
  assert.equal(report.safe, false);
});

test('archives reject traversal even when normalization would stay inside', async () => {
  const report = await inspectTar(makeTar([file('a/../b', 'x')]));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_PATH_TRAVERSAL');
});

for (const bad of ['../evil', '/evil', 'C:/evil', 'a\\evil', 'a//evil']) {
  test('archive member attack rejected: ' + bad, async () => {
    const report = await inspectTar(makeTar([file(bad, 'x')]));
    assert.equal(report.safe, false);
  });
}

for (let length = 90; length <= 110; length += 5) {
  test('long safe component length accepted around ustar boundary ' + length, () => {
    const value = 'd/' + 'x'.repeat(length);
    assert.equal(validateTarPath(value).valid, true);
  });
}
