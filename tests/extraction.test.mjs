import test from 'node:test';
import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { access, chmod, lstat, mkdir, mkdtemp, readFile, readdir, readlink, rm, stat, symlink as makeSymlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { extractTar, inspectTar } from '../src/index.mjs';
import { writeFileChunkFully } from '../src/extract.mjs';
import { directory, file, gzip, hardlink, makeTar, symlink } from './helpers.mjs';

async function tempDir() {
  return mkdtemp(path.join(os.tmpdir(), 'tarcage-extract-'));
}

async function cleanup(dir) {
  await rm(dir, { recursive: true, force: true });
}

async function exists(target) {
  try {
    await access(target);
    return true;
  } catch {
    return false;
  }
}

async function fileMode(target) {
  return (await stat(target)).mode & 0o7777;
}

async function extractToTemp(archive, options = {}) {
  const base = await tempDir();
  const dest = path.join(base, 'out');
  try {
    const report = await extractTar(archive, dest, options);
    return { base, dest, report };
  } catch (error) {
    await cleanup(base);
    throw error;
  }
}

test('extracts a simple file with exact bytes', async () => {
  const base = await tempDir();
  try {
    const dest = path.join(base, 'out');
    const report = await extractTar(makeTar([file('hello.txt', 'hello')]), dest);
    assert.equal(report.extracted, 1);
    assert.equal(report.files, 1);
    assert.equal(report.bytesWritten, 5);
    assert.equal(await readFile(path.join(dest, 'hello.txt'), 'utf8'), 'hello');
  } finally {
    await cleanup(base);
  }
});

test('extracts nested directories and implicit parents', async () => {
  const result = await extractToTemp(makeTar([file('a/b/c/deep.txt', 'deep')]));
  try {
    assert.equal(await readFile(path.join(result.dest, 'a/b/c/deep.txt'), 'utf8'), 'deep');
    assert.equal((await stat(path.join(result.dest, 'a/b'))).isDirectory(), true);
  } finally {
    await cleanup(result.base);
  }
});

test('extracts gzip-compressed archives', async () => {
  const result = await extractToTemp(gzip(makeTar([file('gz.txt', 'gzip data')])));
  try {
    assert.equal(await readFile(path.join(result.dest, 'gz.txt'), 'utf8'), 'gzip data');
  } finally {
    await cleanup(result.base);
  }
});

test('extracts archives read from file paths', async () => {
  const base = await tempDir();
  try {
    const archivePath = path.join(base, 'input.tar.gz');
    await writeFile(archivePath, gzip(makeTar([file('path.txt', 'path input')])));
    const dest = path.join(base, 'out');
    const report = await extractTar(archivePath, dest);
    assert.equal(report.files, 1);
    assert.equal(await readFile(path.join(dest, 'path.txt'), 'utf8'), 'path input');
  } finally {
    await cleanup(base);
  }
});

test('extraction report includes counts and digest', async () => {
  const result = await extractToTemp(makeTar([directory('d/'), file('d/a', '1'), file('d/b', '22')]));
  try {
    assert.equal(result.report.dryRun, false);
    assert.equal(result.report.extracted, 3);
    assert.equal(result.report.files, 2);
    assert.equal(result.report.directories, 1);
    assert.equal(result.report.bytesWritten, 3);
    assert.equal(result.report.uncompressedSha256.length, 64);
  } finally {
    await cleanup(result.base);
  }
});

test('root directory entry is skipped without changing the root', async () => {
  const result = await extractToTemp(makeTar([directory('./'), file('a', 'x')]));
  try {
    assert.equal(result.report.skipped, 1);
    assert.equal(await readFile(path.join(result.dest, 'a'), 'utf8'), 'x');
  } finally {
    await cleanup(result.base);
  }
});

const modeCases = [
  ['plain file mode masks group and other write bits', 0o666, 0o644],
  ['executable file preserves execute bits', 0o777, 0o755],
  ['read-only file remains read-only', 0o444, 0o444],
  ['setuid bit is stripped', 0o4755, 0o755],
  ['setgid bit is stripped', 0o2755, 0o755],
  ['sticky bit is stripped', 0o1755, 0o755]
];

for (const [name, archiveMode, expected] of modeCases) {
  test(name, async () => {
    const result = await extractToTemp(makeTar([file('mode-file', 'x', { mode: archiveMode })]));
    try {
      if (process.platform !== 'win32') assert.equal(await fileMode(path.join(result.dest, 'mode-file')), expected);
    } finally {
      await cleanup(result.base);
    }
  });
}

test('custom zero umask preserves permissive archive mode after special-bit stripping', async () => {
  const result = await extractToTemp(makeTar([file('wide', 'x', { mode: 0o777 })]), { umask: 0 });
  try {
    if (process.platform !== 'win32') assert.equal(await fileMode(path.join(result.dest, 'wide')), 0o777);
  } finally {
    await cleanup(result.base);
  }
});

test('custom restrictive umask is enforced', async () => {
  const result = await extractToTemp(makeTar([file('locked', 'x', { mode: 0o777 })]), { umask: 0o077 });
  try {
    if (process.platform !== 'win32') assert.equal(await fileMode(path.join(result.dest, 'locked')), 0o700);
  } finally {
    await cleanup(result.base);
  }
});

test('explicit directory mode is applied to created directories', async () => {
  const result = await extractToTemp(makeTar([directory('d/', { mode: 0o700 }), file('d/a', 'x')]));
  try {
    if (process.platform !== 'win32') assert.equal(await fileMode(path.join(result.dest, 'd')), 0o700);
  } finally {
    await cleanup(result.base);
  }
});

test('existing destination directory can be reused', async () => {
  const base = await tempDir();
  try {
    const dest = path.join(base, 'out');
    await mkdir(dest);
    const report = await extractTar(makeTar([file('a', 'x')]), dest);
    assert.equal(report.extracted, 1);
  } finally {
    await cleanup(base);
  }
});

test('destination existing as a regular file is refused', async () => {
  const base = await tempDir();
  try {
    const dest = path.join(base, 'out');
    await writeFile(dest, 'keep');
    await assert.rejects(extractTar(makeTar([file('a', 'x')]), dest), (error) => error.code === 'TARCAGE_EXTRACTION_REFUSED');
    assert.equal(await readFile(dest, 'utf8'), 'keep');
  } finally {
    await cleanup(base);
  }
});

test('existing output file is never overwritten', async () => {
  const base = await tempDir();
  try {
    const dest = path.join(base, 'out');
    await mkdir(dest);
    await writeFile(path.join(dest, 'a'), 'original');
    await assert.rejects(extractTar(makeTar([file('a', 'new')]), dest), (error) => error.code === 'TARCAGE_EXTRACTION_OVERWRITE');
    assert.equal(await readFile(path.join(dest, 'a'), 'utf8'), 'original');
  } finally {
    await cleanup(base);
  }
});

test('rollback removes files created before a later extraction failure', async () => {
  const base = await tempDir();
  try {
    const dest = path.join(base, 'out');
    await mkdir(dest);
    await writeFile(path.join(dest, 'blocker'), 'keep');
    const archive = makeTar([file('first', 'created'), file('blocker', 'new')]);
    await assert.rejects(extractTar(archive, dest), (error) => error.code === 'TARCAGE_EXTRACTION_OVERWRITE');
    assert.equal(await exists(path.join(dest, 'first')), false);
    assert.equal(await readFile(path.join(dest, 'blocker'), 'utf8'), 'keep');
  } finally {
    await cleanup(base);
  }
});

test('preflight failure does not create the destination root', async () => {
  const base = await tempDir();
  try {
    const dest = path.join(base, 'out');
    await assert.rejects(extractTar(makeTar([file('../evil', 'x')]), dest), (error) => error.code === 'TARCAGE_EXTRACTION_REFUSED');
    assert.equal(await exists(dest), false);
  } finally {
    await cleanup(base);
  }
});

test('destination root symlink is rejected when supported by the platform', async () => {
  const base = await tempDir();
  try {
    const real = path.join(base, 'real');
    const link = path.join(base, 'link');
    await mkdir(real);
    try {
      await makeSymlink(real, link, 'dir');
    } catch (error) {
      if (process.platform === 'win32') return;
      throw error;
    }
    await assert.rejects(extractTar(makeTar([file('a', 'x')]), link), (error) => error.code === 'TARCAGE_EXTRACTION_SYMLINK');
  } finally {
    await cleanup(base);
  }
});

test('pre-existing symlinked parent directory is never followed', async () => {
  const base = await tempDir();
  try {
    const dest = path.join(base, 'out');
    const outside = path.join(base, 'outside');
    await mkdir(dest);
    await mkdir(outside);
    try {
      await makeSymlink(outside, path.join(dest, 'parent'), 'dir');
    } catch (error) {
      if (process.platform === 'win32') return;
      throw error;
    }
    await assert.rejects(extractTar(makeTar([file('parent/a', 'x')]), dest), (error) => error.code === 'TARCAGE_EXTRACTION_SYMLINK');
    assert.equal(await exists(path.join(outside, 'a')), false);
  } finally {
    await cleanup(base);
  }
});

test('dry run reports the plan without creating destination', async () => {
  const base = await tempDir();
  try {
    const dest = path.join(base, 'out');
    const report = await extractTar(makeTar([directory('d/'), file('d/a', '1234')]), dest, { dryRun: true });
    assert.equal(report.dryRun, true);
    assert.equal(report.extracted, 2);
    assert.equal(report.bytesPlanned, 4);
    assert.equal(await exists(dest), false);
  } finally {
    await cleanup(base);
  }
});

for (const strip of [0, 1, 2]) {
  test('stripComponents ' + strip + ' produces expected layout', async () => {
    const archive = makeTar([directory('root/'), directory('root/sub/'), file('root/sub/a.txt', 'A'), file('root/top.txt', 'T')]);
    const result = await extractToTemp(archive, { stripComponents: strip });
    try {
      if (strip === 0) assert.equal(await readFile(path.join(result.dest, 'root/sub/a.txt'), 'utf8'), 'A');
      if (strip === 1) assert.equal(await readFile(path.join(result.dest, 'sub/a.txt'), 'utf8'), 'A');
      if (strip === 2) assert.equal(await readFile(path.join(result.dest, 'a.txt'), 'utf8'), 'A');
      assert.equal(result.report.skipped, [0, 1, 3][strip]);
    } finally {
      await cleanup(result.base);
    }
  });
}

test('stripComponents collisions are rejected before writing', async () => {
  const base = await tempDir();
  try {
    const dest = path.join(base, 'out');
    const archive = makeTar([file('a/same', '1'), file('b/same', '2')]);
    await assert.rejects(extractTar(archive, dest, { stripComponents: 1 }), (error) => error.code === 'TARCAGE_EXTRACTION_REFUSED' || error.code === 'TARCAGE_DUPLICATE_PATH');
    assert.equal(await exists(dest), false);
  } finally {
    await cleanup(base);
  }
});

test('hardlink extraction creates a second name for the same file', async () => {
  const result = await extractToTemp(makeTar([file('target', 'hard data'), hardlink('copy', 'target')]), { allowHardlinks: true });
  try {
    const targetStat = await stat(path.join(result.dest, 'target'));
    const copyStat = await stat(path.join(result.dest, 'copy'));
    assert.equal(copyStat.ino, targetStat.ino);
    assert.equal(await readFile(path.join(result.dest, 'copy'), 'utf8'), 'hard data');
    assert.equal(result.report.hardlinks, 1);
  } finally {
    await cleanup(result.base);
  }
});

test('hardlink target is rewritten with stripComponents', async () => {
  const result = await extractToTemp(makeTar([
    file('root/target', 'hard data'),
    hardlink('root/copy', 'root/target')
  ]), { allowHardlinks: true, stripComponents: 1 });
  try {
    assert.equal(await readFile(path.join(result.dest, 'copy'), 'utf8'), 'hard data');
    assert.equal((await stat(path.join(result.dest, 'copy'))).ino, (await stat(path.join(result.dest, 'target'))).ino);
  } finally {
    await cleanup(result.base);
  }
});

test('hardlink to a prior hardlink resolves to the same regular file', async () => {
  const result = await extractToTemp(makeTar([
    file('target', 'x'),
    hardlink('first', 'target'),
    hardlink('second', 'first')
  ]), { allowHardlinks: true });
  try {
    assert.equal((await stat(path.join(result.dest, 'second'))).ino, (await stat(path.join(result.dest, 'target'))).ino);
  } finally {
    await cleanup(result.base);
  }
});

for (const [name, entries] of [
  ['missing target', [hardlink('copy', 'missing')]],
  ['forward target', [hardlink('copy', 'target'), file('target', 'x')]],
  ['directory target', [directory('target/'), hardlink('copy', 'target')]]
]) {
  test('hardlink extraction refused for ' + name, async () => {
    const base = await tempDir();
    try {
      const dest = path.join(base, 'out');
      await assert.rejects(extractTar(makeTar(entries), dest, { allowHardlinks: true }), (error) => error.code === 'TARCAGE_EXTRACTION_REFUSED');
      assert.equal(await exists(dest), false);
    } finally {
      await cleanup(base);
    }
  });
}

test('valid symlink extraction creates the archive link target', async () => {
  const archive = makeTar([file('target', 'x'), symlink('link', 'target')]);
  const base = await tempDir();
  try {
    const dest = path.join(base, 'out');
    try {
      const report = await extractTar(archive, dest, { allowSymlinks: true });
      assert.equal(report.symlinks, 1);
      assert.equal(await readlink(path.join(dest, 'link')), 'target');
    } catch (error) {
      if (process.platform !== 'win32') throw error;
    }
  } finally {
    await cleanup(base);
  }
});

test('valid nested symlink chain extracts when enabled', async () => {
  const archive = makeTar([file('target', 'x'), symlink('b', 'target'), symlink('a', 'b')]);
  const base = await tempDir();
  try {
    const dest = path.join(base, 'out');
    try {
      await extractTar(archive, dest, { allowSymlinks: true });
      assert.equal(await readlink(path.join(dest, 'a')), 'b');
    } catch (error) {
      if (process.platform !== 'win32') throw error;
    }
  } finally {
    await cleanup(base);
  }
});

test('symlink static escape is refused before writing', async () => {
  const base = await tempDir();
  try {
    const dest = path.join(base, 'out');
    await assert.rejects(extractTar(makeTar([symlink('link', '../evil')]), dest, { allowSymlinks: true }), (error) => error.code === 'TARCAGE_EXTRACTION_REFUSED');
    assert.equal(await exists(dest), false);
  } finally {
    await cleanup(base);
  }
});

test('symlink resolution through a foreign disk symlink is rolled back', async () => {
  const base = await tempDir();
  try {
    const dest = path.join(base, 'out');
    const outside = path.join(base, 'outside');
    await mkdir(dest);
    await mkdir(outside);
    try {
      await makeSymlink(outside, path.join(dest, 'foreign'), 'dir');
    } catch (error) {
      if (process.platform === 'win32') return;
      throw error;
    }
    const archive = makeTar([file('safe', 'x'), symlink('link', 'foreign/inside')]);
    await assert.rejects(extractTar(archive, dest, { allowSymlinks: true }), (error) => error.code === 'TARCAGE_EXTRACTION_SYMLINK');
    assert.equal(await exists(path.join(dest, 'safe')), false);
    assert.equal(await exists(path.join(dest, 'link')), false);
    assert.equal(await exists(path.join(dest, 'foreign')), true);
  } finally {
    await cleanup(base);
  }
});

test('special entries are never extracted even when inspection allows them', async () => {
  const base = await tempDir();
  try {
    const dest = path.join(base, 'out');
    const archive = makeTar([{ name: 'fifo', typeflag: '6', content: '', size: 0 }]);
    await assert.rejects(extractTar(archive, dest, { allowSpecialFiles: true }), (error) => error.code === 'TARCAGE_EXTRACTION_REFUSED');
    assert.equal(await exists(dest), false);
  } finally {
    await cleanup(base);
  }
});

test('large file streams to disk within entry cap', async () => {
  const content = Buffer.alloc(1024 * 1024, 65);
  const result = await extractToTemp(makeTar([file('large.bin', content)]), { maxEntryBytes: 1024 * 1024 });
  try {
    assert.equal((await stat(path.join(result.dest, 'large.bin'))).size, content.length);
    assert.equal(result.report.bytesWritten, content.length);
  } finally {
    await cleanup(result.base);
  }
});

test('entry larger than maxEntryBytes is refused before writing', async () => {
  const base = await tempDir();
  try {
    const dest = path.join(base, 'out');
    const archive = makeTar([file('big', Buffer.alloc(2048, 65))]);
    await assert.rejects(extractTar(archive, dest, { maxEntryBytes: 1024 }), (error) => error.code === 'TARCAGE_EXTRACTION_REFUSED');
    assert.equal(await exists(dest), false);
  } finally {
    await cleanup(base);
  }
});

test('unicode filenames extract correctly', async () => {
  const result = await extractToTemp(makeTar([file('caf\u00e9/\u6587\u4ef6.txt', 'unicode')]));
  try {
    assert.equal(await readFile(path.join(result.dest, 'caf\u00e9/\u6587\u4ef6.txt'), 'utf8'), 'unicode');
  } finally {
    await cleanup(result.base);
  }
});

test('filenames with interior spaces extract correctly', async () => {
  const result = await extractToTemp(makeTar([file('my file.txt', 'spaces')]));
  try {
    assert.equal(await readFile(path.join(result.dest, 'my file.txt'), 'utf8'), 'spaces');
  } finally {
    await cleanup(result.base);
  }
});

test('deep directory trees extract correctly', async () => {
  const deep = Array.from({ length: 12 }, (_, index) => 'd' + index).join('/') + '/file.txt';
  const result = await extractToTemp(makeTar([file(deep, 'deep')]));
  try {
    assert.equal(await readFile(path.join(result.dest, deep), 'utf8'), 'deep');
  } finally {
    await cleanup(result.base);
  }
});

test('empty files are created correctly', async () => {
  const result = await extractToTemp(makeTar([file('empty', '')]));
  try {
    assert.equal((await stat(path.join(result.dest, 'empty'))).size, 0);
  } finally {
    await cleanup(result.base);
  }
});

test('multiple entries in one archive extract in order', async () => {
  const entries = [];
  for (let index = 0; index < 10; index += 1) entries.push(file('f' + index, String(index)));
  const result = await extractToTemp(makeTar(entries));
  try {
    assert.equal((await readdir(result.dest)).length, 10);
    for (let index = 0; index < 10; index += 1) assert.equal(await readFile(path.join(result.dest, 'f' + index), 'utf8'), String(index));
  } finally {
    await cleanup(result.base);
  }
});

test('extraction digest matches inspection digest for identical input', async () => {
  const archive = makeTar([file('safe', 'x')]);
  const inspection = await inspectTar(archive);
  const result = await extractToTemp(archive);
  try {
    assert.equal(result.report.uncompressedSha256, inspection.stats.uncompressedSha256);
  } finally {
    await cleanup(result.base);
  }
});

for (const badPath of ['../evil', '/evil', 'C:/evil', 'a\\evil']) {
  test('extraction refuses malicious path ' + badPath + ' before writing', async () => {
    const base = await tempDir();
    try {
      const dest = path.join(base, 'out');
      await assert.rejects(extractTar(makeTar([file(badPath, 'x')]), dest), (error) => error.code === 'TARCAGE_EXTRACTION_REFUSED');
      assert.equal(await exists(dest), false);
    } finally {
      await cleanup(base);
    }
  });
}

test('invalid destination type throws input error', async () => {
  await assert.rejects(extractTar(makeTar([file('a', 'x')]), ''), (error) => error.code === 'TARCAGE_INVALID_INPUT');
});

test('existing directories are not chmodded by archive entries', async () => {
  const base = await tempDir();
  try {
    const dest = path.join(base, 'out');
    await mkdir(path.join(dest, 'd'), { recursive: true, mode: 0o755 });
    const before = process.platform === 'win32' ? 0 : await fileMode(path.join(dest, 'd'));
    await extractTar(makeTar([directory('d/', { mode: 0o700 }), file('d/a', 'x')]), dest);
    if (process.platform !== 'win32') assert.equal(await fileMode(path.join(dest, 'd')), before);
  } finally {
    await cleanup(base);
  }
});

test('file chunk writer completes partial filesystem writes in order', async () => {
  const pieces = [];
  const handle = {
    async write(buffer, offset, length) {
      const amount = Math.min(2, length);
      pieces.push(Buffer.from(buffer.subarray(offset, offset + amount)));
      return { bytesWritten: amount };
    }
  };
  const total = await writeFileChunkFully(handle, Buffer.from('abcdef'), 'partial-test');
  assert.equal(total, 6);
  assert.equal(Buffer.concat(pieces).toString('utf8'), 'abcdef');
});

test('file chunk writer rejects a zero-progress filesystem write', async () => {
  const handle = {
    async write() {
      return { bytesWritten: 0 };
    }
  };
  await assert.rejects(writeFileChunkFully(handle, Buffer.from('abc'), 'zero-progress'), (error) => error.code === 'TARCAGE_EXTRACTION_IO');
});

test('restrictive directory modes are deferred until child entries are written', async () => {
  const result = await extractToTemp(makeTar([directory('d/', { mode: 0o444 }), file('d/a', 'x')]));
  try {
    assert.equal(result.report.extracted, 2);
    if (process.platform !== 'win32') assert.equal(await fileMode(path.join(result.dest, 'd')), 0o444);
    await chmod(path.join(result.dest, 'd'), 0o700).catch(() => {});
    assert.equal(await readFile(path.join(result.dest, 'd/a'), 'utf8'), 'x');
  } finally {
    await chmod(path.join(result.dest, 'd'), 0o700).catch(() => {});
    await cleanup(result.base);
  }
});

test('rollback removes created files even when an archive declares restrictive directory modes', async () => {
  const base = await tempDir();
  try {
    const dest = path.join(base, 'out');
    await mkdir(dest);
    await writeFile(path.join(dest, 'blocker'), 'keep');
    const archive = makeTar([file('d/secret', 'x'), directory('d/', { mode: 0o444 }), file('blocker', 'new')]);
    await assert.rejects(extractTar(archive, dest), (error) => error.code === 'TARCAGE_EXTRACTION_OVERWRITE');
    assert.equal(await exists(path.join(dest, 'd/secret')), false);
    assert.equal(await exists(path.join(dest, 'd')), false);
    assert.equal(await readFile(path.join(dest, 'blocker'), 'utf8'), 'keep');
  } finally {
    await chmod(path.join(base, 'out', 'd'), 0o700).catch(() => {});
    await cleanup(base);
  }
});
