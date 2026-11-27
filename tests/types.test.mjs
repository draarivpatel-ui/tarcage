import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as runtime from '../src/index.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const declarationsPath = path.join(root, 'types', 'index.d.ts');
const declarations = await readFile(declarationsPath, 'utf8');

const exportedFunctions = [
  'createTarPolicy',
  'sanitizeMode',
  'validateTarPath',
  'assertValidTarPath',
  'collisionKey',
  'validateSymlinkTarget',
  'validateHardlinkTarget',
  'resolveSymlinkWithinRoot',
  'resolveRootRelativeWithinRoot',
  'inspectTar',
  'auditTar',
  'parseTar',
  'listTarEntries',
  'extractTar'
];

for (const name of exportedFunctions) {
  test('declaration declares exported function ' + name, () => {
    assert.match(declarations, new RegExp('export function ' + name + '\\b'));
    assert.equal(typeof runtime[name], 'function');
  });
}

const exportedClasses = [
  'TarCageError',
  'TarInputError',
  'TarPolicyError',
  'TarFormatError',
  'TarChecksumError',
  'TarPathError',
  'TarLinkError',
  'TarLimitError',
  'TarExtractionError',
  'TarCliError'
];

for (const name of exportedClasses) {
  test('declaration declares error class ' + name, () => {
    assert.match(declarations, new RegExp('export class ' + name + '\\b'));
    assert.equal(typeof runtime[name], 'function');
    assert.equal(Object.prototype.isPrototypeOf.call(runtime.TarCageError, runtime[name]) || name === 'TarCageError', true);
  });
}

test('declaration exports version constant matching runtime version', () => {
  assert.match(declarations, /export const TARCAGE_VERSION: string;/);
  assert.equal(runtime.TARCAGE_VERSION, '1.0.0');
});

test('declaration exports immutable policy and error-code constants', () => {
  assert.match(declarations, /export const TARCAGE_ERROR_CODES: Readonly<Record<string, string>>;/);
  assert.match(declarations, /export const DEFAULT_TAR_POLICY: Readonly<TarPolicy>;/);
  assert.equal(Object.isFrozen(runtime.DEFAULT_TAR_POLICY), true);
});

test('declaration avoids explicit any types', () => {
  assert.equal(/\bany\b/.test(declarations), false);
});

test('declaration includes every public policy option', () => {
  for (const key of Object.keys(runtime.DEFAULT_TAR_POLICY)) {
    assert.ok(declarations.includes(key + '?:'), 'missing policy option ' + key);
  }
});

test('declaration includes stable report interfaces', () => {
  for (const name of [
    'TarPolicyOptions',
    'TarPolicy',
    'TarFinding',
    'TarEntry',
    'TarStats',
    'TarParseResult',
    'TarInspectReport',
    'TarAuditReport',
    'TarValidationResult',
    'TarExtractReport',
    'TarDryRunReport'
  ]) {
    assert.match(declarations, new RegExp('export interface ' + name + '\\b'));
  }
});

test('declaration models audit verdict as a safe or unsafe union', () => {
  assert.match(declarations, /verdict: 'safe' \| 'unsafe';/);
});

test('declaration models input as Buffer Uint8Array or string', () => {
  assert.match(declarations, /export type TarInput = Buffer \| Uint8Array \| string;/);
});

test('declaration models dry-run extraction as a distinct report type', () => {
  assert.match(declarations, /export interface TarDryRunReport extends TarExtractReport/);
  assert.match(declarations, /dryRun: true;/);
  assert.match(declarations, /bytesPlanned: number;/);
});

test('declaration exposes entry type and archive format unions', () => {
  assert.match(declarations, /export type TarEntryType =/);
  assert.match(declarations, /'character-device'/);
  assert.match(declarations, /export type TarFormat = 'pax' \| 'gnu' \| 'ustar' \| 'v7' \| 'unknown';/);
});

test('declaration promises async archive APIs', () => {
  for (const name of ['inspectTar', 'auditTar', 'parseTar', 'listTarEntries', 'extractTar']) {
    assert.match(declarations, new RegExp('export function ' + name + '\\([^;]+: Promise<'));
  }
});

test('runtime exports have no undocumented extra function API', () => {
  const runtimeFunctions = Object.keys(runtime).filter((key) => typeof runtime[key] === 'function' && !/Error$/.test(key));
  for (const key of runtimeFunctions) {
    assert.ok(exportedFunctions.includes(key), 'undocumented runtime export ' + key);
  }
});

test('package types field and exports map point at declarations', async () => {
  const pkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.types, './types/index.d.ts');
  assert.equal(pkg.exports['.'].types, './types/index.d.ts');
});

test('declaration uses only Node built-in type references', () => {
  const references = declarations.match(/<reference types="[^"]+" \/>/g) || [];
  assert.deepEqual(references, ['<reference types="node" />']);
});

test('declaration uses immutable readonly containers where exposed as constants', () => {
  assert.match(declarations, /Readonly<Record<string, string>>/);
  assert.match(declarations, /Readonly<TarPolicy>/);
  assert.match(declarations, /ReadonlyMap<string, string>/);
});
