import test from 'node:test';
import assert from 'node:assert/strict';
import { access, readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const EXPECTED_TEST_COUNT = 673;
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SKIP_ENTRIES = new Set(['.git', 'node_modules', '.DS_Store']);

async function walk(directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (SKIP_ENTRIES.has(entry.name)) continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) output.push(...await walk(full));
    else if (entry.isFile()) output.push(full);
  }
  return output.sort();
}

async function trackedTextFiles() {
  return walk(root);
}

async function readRoot(...parts) {
  return readFile(path.join(root, ...parts), 'utf8');
}

test('repository text files contain no em or en dash characters', async () => {
  const emDash = String.fromCharCode(0x2014);
  const enDash = String.fromCharCode(0x2013);
  for (const file of await trackedTextFiles()) {
    const text = await readFile(file, 'utf8');
    assert.equal(text.includes(emDash), false, file + ' contains an em dash');
    assert.equal(text.includes(enDash), false, file + ' contains an en dash');
  }
});

test('repository text files contain no local paths or private account data', async () => {
  const banned = [
    new RegExp('/' + 'Users' + '/'),
    new RegExp('Hub' + '/' + 'personal'),
    new RegExp('Contest' + ' ' + 'Submissions'),
    new RegExp('@' + 'gmail'),
    new RegExp('t3' + '-code', 'i'),
    new RegExp('pro' + 'ro' + 'blox', 'i')
  ];
  for (const file of await trackedTextFiles()) {
    const raw = await readFile(file, 'utf8');
    const text = raw
      .replaceAll('287273626+draarivpatel-ui@users.noreply.github.com', '')
      .replaceAll('draarivpatel-ui', '');
    for (const pattern of banned) {
      assert.equal(pattern.test(text), false, file + ' contains ' + pattern);
    }
    assert.equal(new RegExp('aa' + 'riv' + 'patel', 'i').test(text), false, file + ' contains a private account string');
  }
});

test('repository text files use LF line endings', async () => {
  for (const file of await trackedTextFiles()) {
    const text = await readFile(file, 'utf8');
    assert.equal(text.includes('\r'), false, file + ' contains CR');
  }
});

test('repository files contain no secret-shaped placeholders with vendor prefixes', async () => {
  const patterns = [
    new RegExp('ts' + 'key-'),
    new RegExp('s' + 'k-[A-Za-z0-9]'),
    new RegExp('gh' + 'p_[A-Za-z0-9]'),
    new RegExp('github' + '_pat_[A-Za-z0-9]'),
    new RegExp('AK' + 'IA[0-9A-Z]'),
    new RegExp('x' + 'ox[baprs]-'),
    new RegExp('nv' + 'api-'),
    new RegExp('AI' + 'za[0-9A-Za-z_-]')
  ];
  for (const file of await trackedTextFiles()) {
    const text = await readFile(file, 'utf8');
    for (const pattern of patterns) {
      assert.equal(pattern.test(text), false, file + ' contains ' + pattern);
    }
  }
});

test('README deterministic test count matches the verified live count', async () => {
  const readme = await readRoot('README.md');
  const match = readme.match(/\b(\d+) deterministic tests\b/i);
  assert.ok(match, 'README does not state the deterministic test count');
  assert.equal(Number(match[1]), EXPECTED_TEST_COUNT);
});

test('README states limitations and supported Node versions', async () => {
  const readme = await readRoot('README.md');
  assert.match(readme, /Node 18 or newer/i);
  assert.match(readme, /## Limitations/);
  assert.match(readme, /Sparse files, multi-volume archives/i);
});

test('README documents the major attack classes without hype', async () => {
  const readme = await readRoot('README.md');
  for (const fragment of ['CVE-2007-4559', 'CWE-22', 'CWE-59', 'CWE-61', 'CWE-409', 'parser differentials', 'gzip resource exhaustion']) {
    assert.ok(readme.includes(fragment), 'missing README fragment ' + fragment);
  }
  assert.equal(/guaranteed|military grade|unbreakable/i.test(readme), false);
});

test('README documents CLI exit codes', async () => {
  const readme = await readRoot('README.md');
  assert.match(readme, /`0`: safe under the active policy/);
  assert.match(readme, /`1`: unsafe findings or extraction refusal/);
  assert.match(readme, /`2`: command-line usage, invalid options, or input-file errors/);
});

test('security documentation includes a reporting channel and scope', async () => {
  const security = await readRoot('SECURITY.md');
  assert.match(security, /Report suspected vulnerabilities privately/i);
  assert.match(security, /Supported versions/i);
  assert.match(security, /CWE-22/);
  assert.match(security, /CWE-409/);
  assert.match(security, /Out of scope/i);
});

test('contributing documentation preserves zero-dependency fail-closed rules', async () => {
  const text = await readRoot('CONTRIBUTING.md');
  assert.match(text, /zero-dependency/);
  assert.match(text, /fail-closed/);
  assert.match(text, /fs\.readdirSync/);
  assert.match(text, /Node 18 or newer/);
});

test('license is MIT with the public maintainer identity', async () => {
  const license = await readRoot('LICENSE');
  assert.match(license, /MIT License/);
  assert.match(license, /Copyright \(c\) 2026 draarivpatel-ui/);
  assert.match(license, /Permission is hereby granted/);
});

test('GitHub workflow covers the required eight job matrix', async () => {
  const workflow = await readRoot('.github', 'workflows', 'ci.yml');
  assert.match(workflow, /os: \[ubuntu-24\.04, windows-latest\]/);
  assert.match(workflow, /node: \[18, 20, 22, 24\]/);
  assert.match(workflow, /fail-fast: false/);
});

test('GitHub workflow runs tests and package dry run', async () => {
  const workflow = await readRoot('.github', 'workflows', 'ci.yml');
  assert.match(workflow, /node scripts\/run-tests\.mjs/);
  assert.match(workflow, /npm pack --dry-run/);
});

test('gitattributes explicitly enforces LF for every required text extension', async () => {
  const text = await readRoot('.gitattributes');
  for (const line of [
    '.gitattributes text eol=lf',
    '.gitignore text eol=lf',
    'LICENSE text eol=lf',
    '*.mjs text eol=lf',
    '*.js text eol=lf',
    '*.ts text eol=lf',
    '*.d.ts text eol=lf',
    '*.json text eol=lf',
    '*.md text eol=lf',
    '*.yml text eol=lf',
    '*.yaml text eol=lf'
  ]) {
    assert.ok(text.includes(line), 'missing gitattributes line ' + line);
  }
});

test('package has zero runtime dependencies and only the pinned fuzz development dependency', async () => {
  const pkg = JSON.parse(await readRoot('package.json'));
  assert.deepEqual(pkg.dependencies, {});
  assert.deepEqual(Object.keys(pkg.devDependencies), ['fast-check']);
  assert.match(pkg.devDependencies['fast-check'], /^\d+\.\d+\.\d+$/);
  assert.equal(pkg.sideEffects, false);
  assert.equal(pkg.type, 'module');
});

test('package metadata points at the ESM library CLI and declarations', async () => {
  const pkg = JSON.parse(await readRoot('package.json'));
  assert.equal(pkg.main, './src/index.mjs');
  assert.equal(pkg.types, './types/index.d.ts');
  assert.equal(pkg.exports['.'].import, './src/index.mjs');
  assert.equal(pkg.bin.tarcage, './bin/tarcage.mjs');
  assert.equal(pkg.engines.node, '>=18.0.0');
});

test('package release surface excludes tests scratch and workflow internals', async () => {
  const pkg = JSON.parse(await readRoot('package.json'));
  assert.deepEqual(pkg.files, [
    'bin',
    'src',
    'types',
    'examples',
    'README.md',
    'SECURITY.md',
    'CONTRIBUTING.md',
    'CODE_OF_CONDUCT.md',
    'CHANGELOG.md',
    'LICENSE'
  ]);
});

test('package has a reproducible lockfile and no shrinkwrap shadow file', async () => {
  const lock = JSON.parse(await readFile(path.join(root, 'package-lock.json'), 'utf8'));
  assert.equal(lock.packages[''].dependencies, undefined);
  assert.deepEqual(Object.keys(lock.packages[''].devDependencies), ['fast-check']);
  await assert.rejects(access(path.join(root, 'npm-shrinkwrap.json')));
});

test('source CLI and examples avoid eval and dynamic code execution', async () => {
  const files = [
    ...(await readdir(path.join(root, 'src'))).map((name) => path.join(root, 'src', name)),
    path.join(root, 'bin', 'tarcage.mjs'),
    ...(await readdir(path.join(root, 'examples'))).map((name) => path.join(root, 'examples', name))
  ];
  for (const file of files) {
    const text = await readFile(file, 'utf8');
    assert.equal(/\beval\s*\(/.test(text), false, file + ' uses eval');
    assert.equal(/new\s+Function\s*\(/.test(text), false, file + ' uses Function');
  }
});

test('test runner enumerates exact files without shell glob expansion', async () => {
  const text = await readRoot('scripts', 'run-tests.mjs');
  assert.match(text, /fs\.readdirSync|readdirSync/);
  assert.match(text, /tests/);
  assert.equal(text.includes('child_process.exec'), false);
  assert.equal(text.includes('*.test.mjs`'), false);
});

test('POSIX executable mode assertions are guarded for Windows', async () => {
  const extractionTests = await readRoot('tests', 'extraction.test.mjs');
  assert.match(extractionTests, /process\.platform !== 'win32'/);
});

test('CLI file uses strict mode compatible ESM and stable exit-code handling', async () => {
  const cli = await readRoot('bin', 'tarcage.mjs');
  assert.match(cli, /^#!\/usr\/bin\/env node/);
  assert.match(cli, /return positional\.length === 0 && !takeBoolean\(flags, 'help'\) \? 2 : 0/);
  assert.match(cli, /process\.exitCode = await main\(process\.argv\.slice\(2\)\)/);
});

test('examples are present and use the public package name', async () => {
  for (const name of ['inspect.mjs', 'extract.mjs', 'policy.mjs']) {
    const text = await readRoot('examples', name);
    assert.match(text, /from 'tarcage'/);
  }
});

test('repository contains no generated fixture archives or binary media', async () => {
  for (const file of await trackedTextFiles()) {
    assert.equal(/\.(tar|tgz|gz|zip|png|jpg|jpeg|mp4|mov|woff2?)$/i.test(file), false, 'unexpected binary or fixture ' + file);
  }
});

test('repository file count stays within the intended minimal release surface', async () => {
  const files = await trackedTextFiles();
  assert.equal(files.length <= 40, true, 'unexpected repository file growth: ' + files.length);
});

test('tracked files end with exactly one final newline', async () => {
  for (const file of await trackedTextFiles()) {
    const text = await readFile(file, 'utf8');
    assert.equal(text.endsWith('\n'), true, file + ' lacks final newline');
    assert.equal(text.endsWith('\n\n'), false, file + ' ends with a blank line');
  }
});

test('changelog version matches package version', async () => {
  const changelog = await readRoot('CHANGELOG.md');
  const pkg = JSON.parse(await readRoot('package.json'));
  assert.ok(changelog.includes('## [' + pkg.version + ']'), 'changelog missing version ' + pkg.version);
});

test('source error codes use the stable TARCAGE prefix', async () => {
  const errors = await readRoot('src', 'errors.mjs');
  const matches = errors.match(/'TARCAGE_[A-Z0-9_]+'/g) || [];
  assert.equal(matches.length > 10, true);
  assert.equal(matches.some((code) => code.includes('TARCAGE_PATH_TRAVERSAL')), true);
  assert.equal(matches.some((code) => code.includes('TARCAGE_EXTRACTION_REFUSED')), true);
});

test('repository does not contain editor OS or coverage artifacts', async () => {
  const forbidden = new Set(['.coverage', 'coverage', '.nyc_output', '.idea', '.vscode']);
  const top = await readdir(root, { withFileTypes: true });
  for (const entry of top) {
    assert.equal(forbidden.has(entry.name), false, 'unexpected artifact ' + entry.name);
  }
});
