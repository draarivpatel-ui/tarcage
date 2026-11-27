import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createTarPolicy,
  inspectTar,
  listTarEntries,
  resolveRootRelativeWithinRoot,
  resolveSymlinkWithinRoot,
  validateHardlinkTarget,
  validateSymlinkTarget
} from '../src/index.mjs';
import { directory, file, hardlink, makeTar, symlink } from './helpers.mjs';

test('symlink entries are blocked by default', async () => {
  const report = await inspectTar(makeTar([symlink('ln', 'target')]));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_SYMLINK_BLOCKED');
});

test('hardlink entries are blocked by default', async () => {
  const report = await inspectTar(makeTar([hardlink('ln', 'target')]));
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_HARDLINK_BLOCKED');
});

test('confined symlink is accepted when explicitly enabled', async () => {
  const report = await inspectTar(makeTar([file('target', 'x'), symlink('ln', 'target')]), { allowSymlinks: true });
  assert.equal(report.safe, true);
  assert.equal(report.entries[1].type, 'symlink');
});

test('confined hardlink is accepted when explicitly enabled', async () => {
  const report = await inspectTar(makeTar([file('target', 'x'), hardlink('ln', 'target')]), { allowHardlinks: true });
  assert.equal(report.safe, true);
  assert.equal(report.entries[1].type, 'hardlink');
});

test('symlink one parent reference that stays inside root is accepted', async () => {
  const report = await inspectTar(makeTar([
    directory('d/'),
    file('target', 'x'),
    symlink('d/ln', '../target')
  ]), { allowSymlinks: true });
  assert.equal(report.safe, true);
});

for (const target of ['../evil', '../../evil', './../../evil', 'a/../../evil']) {
  test('root symlink escape rejected for ' + target, async () => {
    const report = await inspectTar(makeTar([symlink('ln', target)]), { allowSymlinks: true });
    assert.equal(report.safe, false);
    assert.equal(report.findings[0].code, 'TARCAGE_LINK_ESCAPE');
  });
}

test('nested symlink excessive parent traversal is rejected', async () => {
  const report = await inspectTar(makeTar([symlink('d/ln', '../../evil')]), { allowSymlinks: true });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_LINK_ESCAPE');
});

const invalidLinkTargets = [
  ['empty', '', 'TARCAGE_LINK_INVALID'],
  ['posix absolute', '/etc/passwd', 'TARCAGE_ABSOLUTE_PATH'],
  ['drive absolute', 'C:/evil', 'TARCAGE_DRIVE_PATH'],
  ['drive relative', 'C:evil', 'TARCAGE_DRIVE_PATH'],
  ['unc slashes', '//server/share', 'TARCAGE_UNC_PATH'],
  ['unc backslashes', '\\\\server\\share', 'TARCAGE_UNC_PATH'],
  ['backslash separator', 'a\\evil', 'TARCAGE_BACKSLASH_SEPARATOR'],
  ['nul byte', 'a\0b', 'TARCAGE_MALFORMED_ARCHIVE'],
  ['bidi override', 'a\u202eb', 'TARCAGE_CONTROL_CHARACTER'],
  ['trailing dot component', 'evil./x', 'TARCAGE_TRAILING_DOT_OR_SPACE'],
  ['trailing space component', 'evil /x', 'TARCAGE_TRAILING_DOT_OR_SPACE'],
  ['reserved name', 'NUL.txt', 'TARCAGE_RESERVED_NAME'],
  ['empty interior segment', 'a//b', 'TARCAGE_EMPTY_PATH_SEGMENT']
];

for (const [name, target, code] of invalidLinkTargets) {
  test('symlink target rejected: ' + name, async () => {
    const report = await inspectTar(makeTar([symlink('ln', target)]), { allowSymlinks: true });
    assert.equal(report.safe, false);
    assert.equal(report.findings[0].code, code);
  });

  test('hardlink target rejected: ' + name, async () => {
    const report = await inspectTar(makeTar([hardlink('ln', target)]), { allowHardlinks: true });
    assert.equal(report.safe, false);
  });
}

test('symlink target trailing slash is tolerated as a directory hint', async () => {
  const report = await inspectTar(makeTar([directory('d/'), symlink('ln', 'd/')]), { allowSymlinks: true });
  assert.equal(report.safe, true);
});

test('symlink target maximum path length is enforced', async () => {
  const report = await inspectTar(makeTar([symlink('ln', 'x'.repeat(30))]), { allowSymlinks: true, maxPathLength: 20 });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_PATH_TOO_LONG');
});

test('symlink target maximum component length is enforced', async () => {
  const report = await inspectTar(makeTar([symlink('ln', 'x'.repeat(30))]), { allowSymlinks: true, maxComponentLength: 20 });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_COMPONENT_TOO_LONG');
});

test('symlink chain inside root is accepted', async () => {
  const report = await inspectTar(makeTar([
    file('target', 'x'),
    symlink('b', 'target'),
    symlink('a', 'b')
  ]), { allowSymlinks: true });
  assert.equal(report.safe, true);
});

test('symlink chain escaping through second link is rejected', async () => {
  const report = await inspectTar(makeTar([
    symlink('a', 'b'),
    symlink('b', '../evil')
  ]), { allowSymlinks: true });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_LINK_ESCAPE');
});

test('symlink chain through a symlinked directory is evaluated', async () => {
  const report = await inspectTar(makeTar([
    symlink('dir', '../outside'),
    symlink('a', 'dir/file')
  ]), { allowSymlinks: true });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_LINK_ESCAPE');
});

test('symlink chain lookup is conservative across case differences', async () => {
  const report = await inspectTar(makeTar([
    symlink('Link', '../outside'),
    symlink('a', 'link/file')
  ]), { allowSymlinks: true });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_LINK_ESCAPE');
});

const cycleCases = [
  ['self link', [symlink('a', 'a')]],
  ['two link cycle', [symlink('a', 'b'), symlink('b', 'a')]],
  ['three link cycle', [symlink('a', 'b'), symlink('b', 'c'), symlink('c', 'a')]]
];

for (const [name, entries] of cycleCases) {
  test('cyclic symlink chain rejected: ' + name, async () => {
    const report = await inspectTar(makeTar(entries), { allowSymlinks: true });
    assert.equal(report.safe, false);
    assert.equal(report.findings[0].code, 'TARCAGE_LINK_CHAIN');
  });
}

test('symlink chain depth cap is enforced', async () => {
  const entries = [file('target', 'x')];
  for (let index = 0; index < 6; index += 1) {
    entries.push(symlink('l' + index, index === 5 ? 'target' : 'l' + (index + 1)));
  }
  const report = await inspectTar(makeTar(entries), { allowSymlinks: true, maxSymlinkDepth: 3 });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_LINK_CHAIN');
});

test('hardlink target is interpreted relative to archive root, not containing directory', async () => {
  const entries = await listTarEntries(makeTar([
    directory('d/'),
    file('target', 'x'),
    hardlink('d/link', 'target')
  ]), { allowHardlinks: true });
  assert.equal(entries[2].linkname, 'target');
});

test('hardlink target dot segments are normalized', async () => {
  const entries = await listTarEntries(makeTar([
    file('target', 'x'),
    hardlink('link', './target')
  ]), { allowHardlinks: true });
  assert.equal(entries[1].linkname, 'target');
});

test('hardlink target parent traversal is rejected even when contained', async () => {
  const report = await inspectTar(makeTar([
    file('target', 'x'),
    hardlink('link', 'a/../target')
  ]), { allowHardlinks: true });
  assert.equal(report.safe, false);
});

test('hardlink to itself is rejected', async () => {
  const report = await inspectTar(makeTar([hardlink('link', 'link')]), { allowHardlinks: true });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_LINK_INVALID');
});

test('hardlink through escaping symlinked directory is rejected', async () => {
  const report = await inspectTar(makeTar([
    symlink('dir', '../outside'),
    hardlink('link', 'dir/file')
  ]), { allowSymlinks: true, allowHardlinks: true });
  assert.equal(report.safe, false);
  assert.equal(report.findings[0].code, 'TARCAGE_LINK_ESCAPE');
});

test('hardlink through confined symlinked directory passes static validation', async () => {
  const report = await inspectTar(makeTar([
    directory('real/'),
    symlink('dir', 'real'),
    hardlink('link', 'dir/file')
  ]), { allowSymlinks: true, allowHardlinks: true });
  assert.equal(report.safe, true);
});

test('empty link target in header is malformed', async () => {
  const report = await inspectTar(makeTar([symlink('ln', '')]), { allowSymlinks: true });
  assert.equal(report.safe, false);
});

test('validateSymlinkTarget returns the original target for valid input', () => {
  const policy = createTarPolicy({ allowSymlinks: true });
  assert.equal(validateSymlinkTarget('d/ln', '../target', policy), '../target');
});

test('validateHardlinkTarget returns normalized target', () => {
  const policy = createTarPolicy({ allowHardlinks: true });
  assert.equal(validateHardlinkTarget('ln', './target', policy), 'target');
});

test('validateSymlinkTarget throws for absolute input', () => {
  const policy = createTarPolicy({ allowSymlinks: true });
  assert.throws(() => validateSymlinkTarget('ln', '/x', policy), (error) => error.code === 'TARCAGE_ABSOLUTE_PATH');
});

test('resolveSymlinkWithinRoot resolves nested parent references', () => {
  const policy = createTarPolicy({ allowSymlinks: true });
  assert.equal(resolveSymlinkWithinRoot('a/b/ln', '../../target', new Map(), policy), 'target');
});

test('resolveSymlinkWithinRoot resolves through a map', () => {
  const policy = createTarPolicy({ allowSymlinks: true });
  const map = new Map([['b', 'target']]);
  assert.equal(resolveSymlinkWithinRoot('ln', 'b/file', map, policy), 'target/file');
});

test('resolveRootRelativeWithinRoot rejects escape', () => {
  const policy = createTarPolicy();
  assert.throws(() => resolveRootRelativeWithinRoot('../x', new Map(), policy), (error) => error.code === 'TARCAGE_LINK_ESCAPE');
});

for (const depth of [2, 4, 8]) {
  test('symlink chain within depth limit ' + depth + ' accepted', async () => {
    const entries = [file('target', 'x')];
    for (let index = 0; index < depth; index += 1) {
      entries.push(symlink('l' + index, index === depth - 1 ? 'target' : 'l' + (index + 1)));
    }
    const report = await inspectTar(makeTar(entries), { allowSymlinks: true, maxSymlinkDepth: depth + 2 });
    assert.equal(report.safe, true);
  });
}

for (const target of ['target', './target', 'a/../target', 'd/../../target']) {
  test('validate standalone symlink target shape ' + JSON.stringify(target), () => {
    const policy = createTarPolicy({ allowSymlinks: true });
    assert.equal(validateSymlinkTarget('ln', target, policy), target);
  });
}
