import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const testsDir = path.join(root, 'tests');
const testFiles = fs.readdirSync(testsDir)
  .filter((name) => name.endsWith('.test.mjs'))
  .sort()
  .map((name) => path.join(testsDir, name));

if (testFiles.length === 0) {
  console.error('No tests found in tests/*.test.mjs');
  process.exit(2);
}

const result = spawnSync(process.execPath, ['--test', ...testFiles], {
  cwd: root,
  encoding: 'utf8',
  env: process.env,
  maxBuffer: 64 * 1024 * 1024
});

if (result.stdout) process.stdout.write(result.stdout);
if (result.stderr) process.stderr.write(result.stderr);
if (result.error) {
  console.error('Test runner failed to start: ' + result.error.message);
  process.exit(2);
}

const passMatch = result.stdout.match(/# pass (\d+)/);
if (passMatch) process.stdout.write('tarcage tests passed: ' + passMatch[1] + '\n');
process.exit(result.status === null ? 2 : result.status);
