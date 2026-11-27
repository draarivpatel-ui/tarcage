import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { lstat, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { file, gzip, makeTar } from './helpers.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'bin', 'tarcage.mjs');

function runCli(args, options = {}) {
  return spawnSync(process.execPath, [cli, ...args], {
    encoding: 'utf8',
    cwd: root,
    env: { ...process.env, ...(options.env || {}) }
  });
}

async function fixture() {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'tarcage-cli-'));
  const safeTar = makeTar([file('safe.txt', 'safe')]);
  const evilTar = makeTar([file('../evil.txt', 'evil')]);
  const safePath = path.join(dir, 'safe.tar');
  const evilPath = path.join(dir, 'evil.tar');
  const gzipPath = path.join(dir, 'safe.tar.gz');
  await writeFile(safePath, safeTar);
  await writeFile(evilPath, evilTar);
  await writeFile(gzipPath, gzip(safeTar));
  return { dir, safePath, evilPath, gzipPath };
}

async function cleanup(dir) {
  await rm(dir, { recursive: true, force: true });
}

test('CLI with no arguments prints usage and exits 2', () => {
  const result = runCli([]);
  assert.equal(result.status, 2);
  assert.match(result.stdout, /Usage:/);
});

test('CLI --help prints usage and exits 0', () => {
  const result = runCli(['--help']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /tarcage inspect/);
});

test('CLI --version prints 1.0.0 and exits 0', () => {
  const result = runCli(['--version']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout.trim(), '1.0.0');
});

for (const args of [
  ['unknown'],
  ['inspect'],
  ['audit'],
  ['validate'],
  ['extract'],
  ['inspect', 'x', '--unknown-flag'],
  ['inspect', 'x', '--max-entries'],
  ['inspect', 'x', '--max-entries', 'nope'],
  ['inspect', 'x', '--max-ratio', '-1']
]) {
  test('CLI usage error exits 2 for ' + args.join(' '), () => {
    const result = runCli(args);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /TARCAGE/);
  });
}

test('CLI inspect missing input file exits 2', async () => {
  const result = runCli(['inspect', path.join(os.tmpdir(), 'missing-tarcage-file.tar')]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /TARCAGE_INPUT_IO/);
});

test('CLI inspect safe archive exits 0 with human output', async () => {
  const item = await fixture();
  try {
    const result = runCli(['inspect', item.safePath]);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /safe: yes/);
    assert.match(result.stdout, /format: ustar/);
    assert.match(result.stdout, /entries: 1/);
  } finally {
    await cleanup(item.dir);
  }
});

test('CLI inspect malicious archive exits 1 with finding output', async () => {
  const item = await fixture();
  try {
    const result = runCli(['inspect', item.evilPath]);
    assert.equal(result.status, 1);
    assert.match(result.stdout, /safe: no/);
    assert.match(result.stdout, /TARCAGE_PATH_TRAVERSAL/);
  } finally {
    await cleanup(item.dir);
  }
});

test('CLI inspect safe gzip archive exits 0', async () => {
  const item = await fixture();
  try {
    const result = runCli(['inspect', item.gzipPath]);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /compressed: yes/);
  } finally {
    await cleanup(item.dir);
  }
});

test('CLI inspect --json emits parseable report', async () => {
  const item = await fixture();
  try {
    const result = runCli(['inspect', item.safePath, '--json']);
    assert.equal(result.status, 0);
    const report = JSON.parse(result.stdout);
    assert.equal(report.safe, true);
    assert.equal(report.entries[0].name, 'safe.txt');
    assert.equal(report.stats.entries, 1);
  } finally {
    await cleanup(item.dir);
  }
});

test('CLI inspect malicious --json exits 1 and emits findings', async () => {
  const item = await fixture();
  try {
    const result = runCli(['inspect', item.evilPath, '--json']);
    assert.equal(result.status, 1);
    const report = JSON.parse(result.stdout);
    assert.equal(report.safe, false);
    assert.equal(report.findings.at(-1).code, 'TARCAGE_PATH_TRAVERSAL');
  } finally {
    await cleanup(item.dir);
  }
});

test('CLI audit --json includes verdict and policy', async () => {
  const item = await fixture();
  try {
    const result = runCli(['audit', item.safePath, '--json', '--max-entries', '5']);
    assert.equal(result.status, 0);
    const report = JSON.parse(result.stdout);
    assert.equal(report.verdict, 'safe');
    assert.equal(report.policy.maxEntries, 5);
    assert.equal(Array.isArray(report.recommendations), true);
  } finally {
    await cleanup(item.dir);
  }
});

test('CLI audit unsafe archive exits 1', async () => {
  const item = await fixture();
  try {
    const result = runCli(['audit', item.evilPath, '--json']);
    assert.equal(result.status, 1);
    assert.equal(JSON.parse(result.stdout).verdict, 'unsafe');
  } finally {
    await cleanup(item.dir);
  }
});

for (const [flag, value] of [
  ['--max-entries', '1'],
  ['--max-bytes', '4096'],
  ['--max-compressed-bytes', '4096'],
  ['--max-entry-bytes', '4'],
  ['--max-ratio', '100'],
  ['--max-depth', '2'],
  ['--max-path-length', '100']
]) {
  test('CLI numeric option accepted: ' + flag, async () => {
    const item = await fixture();
    try {
      const result = runCli(['inspect', item.safePath, '--json', flag, value]);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(JSON.parse(result.stdout).safe, true);
    } finally {
      await cleanup(item.dir);
    }
  });
}

for (const [flag, value] of [
  ['--max-entries', '0'],
  ['--max-bytes', 'x'],
  ['--max-entry-bytes', '-1'],
  ['--max-ratio', '0'],
  ['--strip-components', '-1']
]) {
  test('CLI invalid numeric option rejected: ' + flag + ' ' + value, async () => {
    const item = await fixture();
    try {
      const result = runCli(['inspect', item.safePath, flag, value]);
      assert.equal(result.status, 2);
    } finally {
      await cleanup(item.dir);
    }
  });
}

test('CLI equals-form option is accepted', async () => {
  const item = await fixture();
  try {
    const result = runCli(['inspect', item.safePath, '--json', '--max-entries=1']);
    assert.equal(result.status, 0);
    assert.equal(JSON.parse(result.stdout).safe, true);
  } finally {
    await cleanup(item.dir);
  }
});

test('CLI max-entries violation exits 1', async () => {
  const item = await fixture();
  try {
    const result = runCli(['inspect', item.safePath, '--max-entries', '1']);
    assert.equal(result.status, 0);
    const tiny = path.join(item.dir, 'two.tar');
    await writeFile(tiny, makeTar([file('a', '1'), file('b', '2')]));
    const limited = runCli(['inspect', tiny, '--max-entries', '1']);
    assert.equal(limited.status, 1);
  } finally {
    await cleanup(item.dir);
  }
});

for (const value of ['safe/path.txt', './safe.txt', 'a/./b.txt', 'caf\u00e9.txt']) {
  test('CLI validate valid path exits 0: ' + value, () => {
    const result = runCli(['validate', value]);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /valid: yes/);
  });
}

for (const value of ['../evil', '/evil', 'C:/evil', 'a\\evil', 'NUL', 'evil.']) {
  test('CLI validate invalid path exits 1: ' + value, () => {
    const result = runCli(['validate', value]);
    assert.equal(result.status, 1);
    assert.match(result.stdout, /valid: no|TARCAGE_/);
  });
}

test('CLI validate --json emits normalized result', () => {
  const result = runCli(['validate', './a/./b.txt', '--json']);
  assert.equal(result.status, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.valid, true);
  assert.equal(report.normalized, 'a/b.txt');
});

test('CLI validate invalid --json emits findings', () => {
  const result = runCli(['validate', '../evil', '--json']);
  assert.equal(result.status, 1);
  const report = JSON.parse(result.stdout);
  assert.equal(report.valid, false);
  assert.equal(report.findings[0].code, 'TARCAGE_PATH_TRAVERSAL');
});

test('CLI extract safe archive exits 0 and writes files', async () => {
  const item = await fixture();
  try {
    const dest = path.join(item.dir, 'out');
    const result = runCli(['extract', item.safePath, dest]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /extracted: 1/);
    assert.equal(await readFile(path.join(dest, 'safe.txt'), 'utf8'), 'safe');
  } finally {
    await cleanup(item.dir);
  }
});

test('CLI extract --json emits extraction report', async () => {
  const item = await fixture();
  try {
    const dest = path.join(item.dir, 'out');
    const result = runCli(['extract', item.safePath, dest, '--json']);
    assert.equal(result.status, 0);
    const report = JSON.parse(result.stdout);
    assert.equal(report.files, 1);
    assert.equal(report.bytesWritten, 4);
  } finally {
    await cleanup(item.dir);
  }
});

test('CLI extract malicious archive exits 1 and creates nothing', async () => {
  const item = await fixture();
  try {
    const dest = path.join(item.dir, 'out');
    const result = runCli(['extract', item.evilPath, dest]);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /TARCAGE_EXTRACTION_REFUSED/);
    assert.equal(await existsNoThrow(dest), false);
  } finally {
    await cleanup(item.dir);
  }
});

async function existsNoThrow(target) {
  try {
    await lstat(target);
    return true;
  } catch {
    return false;
  }
}

test('CLI extract --dry-run does not create destination', async () => {
  const item = await fixture();
  try {
    const dest = path.join(item.dir, 'dry');
    const result = runCli(['extract', item.safePath, dest, '--dry-run', '--json']);
    assert.equal(result.status, 0);
    assert.equal(JSON.parse(result.stdout).dryRun, true);
  } finally {
    await cleanup(item.dir);
  }
});

test('CLI extract gzip archive works', async () => {
  const item = await fixture();
  try {
    const dest = path.join(item.dir, 'gzip-out');
    const result = runCli(['extract', item.gzipPath, dest]);
    assert.equal(result.status, 0);
    assert.equal(await readFile(path.join(dest, 'safe.txt'), 'utf8'), 'safe');
  } finally {
    await cleanup(item.dir);
  }
});

test('CLI extract strip-components works', async () => {
  const item = await fixture();
  try {
    const nested = path.join(item.dir, 'nested.tar');
    await writeFile(nested, makeTar([file('root/inside.txt', 'nested')]));
    const dest = path.join(item.dir, 'strip-out');
    const result = runCli(['extract', nested, dest, '--strip-components', '1']);
    assert.equal(result.status, 0);
    assert.equal(await readFile(path.join(dest, 'inside.txt'), 'utf8'), 'nested');
  } finally {
    await cleanup(item.dir);
  }
});

test('CLI extract destination existing as file exits 1', async () => {
  const item = await fixture();
  try {
    const dest = path.join(item.dir, 'dest-file');
    await writeFile(dest, 'keep');
    const result = runCli(['extract', item.safePath, dest]);
    assert.equal(result.status, 1);
    assert.equal(await readFile(dest, 'utf8'), 'keep');
  } finally {
    await cleanup(item.dir);
  }
});

test('CLI boolean policy flags are accepted in audit JSON', async () => {
  const item = await fixture();
  try {
    const result = runCli([
      'audit',
      item.safePath,
      '--json',
      '--allow-symlinks',
      '--allow-hardlinks',
      '--allow-special-files',
      '--dry-run'
    ]);
    assert.equal(result.status, 0);
    const report = JSON.parse(result.stdout);
    assert.equal(report.policy.allowSymlinks, true);
    assert.equal(report.policy.allowHardlinks, true);
    assert.equal(report.policy.allowSpecialFiles, true);
  } finally {
    await cleanup(item.dir);
  }
});

for (const command of ['inspect', 'audit']) {
  test('CLI ' + command + ' enforces max entries exit 1', async () => {
    const item = await fixture();
    try {
      const archive = path.join(item.dir, 'two.tar');
      await writeFile(archive, makeTar([file('a', '1'), file('b', '2')]));
      const result = runCli([command, archive, '--max-entries', '1']);
      assert.equal(result.status, 1);
    } finally {
      await cleanup(item.dir);
    }
  });
}

test('CLI missing archive for extract exits 2', async () => {
  const item = await fixture();
  try {
    const result = runCli(['extract', path.join(item.dir, 'missing.tar'), path.join(item.dir, 'out')]);
    assert.equal(result.status, 2);
  } finally {
    await cleanup(item.dir);
  }
});

test('CLI supports a positional archive after double dash', async () => {
  const item = await fixture();
  try {
    const result = runCli(['inspect', '--', item.safePath]);
    assert.equal(result.status, 0);
  } finally {
    await cleanup(item.dir);
  }
});

test('CLI human findings neutralize newline ANSI and bidi characters in archive paths', async () => {
  const item = await fixture();
  try {
    const payload = 'clean\ninjected\x1b[31m\u202e';
    const archivePath = path.join(item.dir, 'terminal.tar');
    await writeFile(archivePath, makeTar([file(payload, 'x')]));
    const result = runCli(['inspect', archivePath]);
    assert.equal(result.status, 1);
    assert.equal(result.stdout.includes('\x1b'), false);
    assert.equal(result.stdout.includes('\u202e'), false);
    assert.equal(result.stdout.includes('clean\\ninjected'), true);
  } finally {
    await cleanup(item.dir);
  }
});

test('CLI JSON output remains parseable while escaping terminal control rendering', async () => {
  const item = await fixture();
  try {
    const payload = 'clean\u202e\x1binjected';
    const archivePath = path.join(item.dir, 'terminal-json.tar');
    await writeFile(archivePath, makeTar([file(payload, 'x')]));
    const result = runCli(['inspect', archivePath, '--json']);
    assert.equal(result.status, 1);
    assert.equal(result.stdout.includes('\x1b'), false);
    assert.equal(result.stdout.includes('\u202e'), false);
    const report = JSON.parse(result.stdout);
    assert.equal(report.findings.at(-1).path, payload);
  } finally {
    await cleanup(item.dir);
  }
});

test('CLI errors neutralize control characters in user-controlled command text', () => {
  const command = 'bad\n\x1b\u202ecommand';
  const result = runCli([command]);
  assert.equal(result.status, 2);
  assert.equal(result.stderr.includes('\x1b'), false);
  assert.equal(result.stderr.includes('\u202e'), false);
  assert.equal(result.stderr.includes('bad\\n'), true);
});
