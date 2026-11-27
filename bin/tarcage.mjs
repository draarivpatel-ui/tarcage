#!/usr/bin/env node

import {
  TARCAGE_VERSION,
  TarCageError,
  TarInputError,
  TarPolicyError,
  auditTar,
  extractTar,
  inspectTar,
  validateTarPath
} from '../src/index.mjs';

const HELP = `tarcage ` + TARCAGE_VERSION + `

Usage:
  tarcage inspect <archive> [options]
  tarcage audit <archive> [options]
  tarcage validate <entry-path> [options]
  tarcage extract <archive> <destination> [options]

Options:
  --json                         write machine-readable JSON
  --max-bytes <n>                maximum uncompressed archive bytes
  --max-compressed-bytes <n>     maximum input bytes
  --max-entry-bytes <n>          maximum bytes in one entry
  --max-entries <n>              maximum archive entries
  --max-ratio <n>                maximum gzip compression ratio
  --max-depth <n>                maximum path depth
  --max-path-length <n>          maximum path byte length
  --strip-components <n>         strip leading path components during extraction
  --allow-symlinks               permit confined symlink entries
  --allow-hardlinks              permit confined hardlink entries
  --allow-special-files          permit inspection of device and FIFO entries
  --dry-run                      validate and report an extraction without writing
  --help                         show this help
  --version                      show the version

Exit codes:
  0  archive or path is safe under the active policy
  1  archive or path is unsafe, or extraction was refused
  2  command-line usage, option, or input-file error
`;

function usageError(message) {
  throw new TarPolicyError('TARCAGE_CLI_USAGE', message);
}

function numberOption(name, value, minimum) {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) usageError(name + ' must be a decimal integer');
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum) usageError(name + ' is outside the supported range');
  return parsed;
}

const VALUE_FLAGS = new Set([
  'max-bytes',
  'max-compressed-bytes',
  'max-entry-bytes',
  'max-entries',
  'max-ratio',
  'max-depth',
  'max-path-length',
  'strip-components'
]);

function parseArgs(argv) {
  const positional = [];
  const flags = new Map();
  let positionalOnly = false;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (positionalOnly) {
      positional.push(arg);
      continue;
    }
    if (arg === '--') {
      positionalOnly = true;
      continue;
    }
    if (!arg.startsWith('--')) {
      positional.push(arg);
      continue;
    }
    const equals = arg.indexOf('=');
    if (equals !== -1) {
      flags.set(arg.slice(2, equals), arg.slice(equals + 1));
    } else {
      const name = arg.slice(2);
      if (VALUE_FLAGS.has(name) && index + 1 < argv.length && !argv[index + 1].startsWith('--')) {
        flags.set(name, argv[index + 1]);
        index += 1;
      } else {
        flags.set(name, true);
      }
    }
  }
  return { positional, flags };
}

function takeValue(flags, name) {
  const value = flags.get(name);
  if (value === undefined) return undefined;
  if (value === true) usageError('--' + name + ' requires a value');
  return value;
}

function takeBoolean(flags, name) {
  const value = flags.get(name);
  if (value === undefined) return false;
  if (value !== true) usageError('--' + name + ' does not take a value');
  return true;
}

function policyFromFlags(flags) {
  const policy = {};
  const numeric = new Map([
    ['max-bytes', 'maxUncompressedBytes'],
    ['max-compressed-bytes', 'maxCompressedBytes'],
    ['max-entry-bytes', 'maxEntryBytes'],
    ['max-entries', 'maxEntries'],
    ['max-depth', 'maxDepth'],
    ['max-path-length', 'maxPathLength'],
    ['strip-components', 'stripComponents']
  ]);
  for (const [flag, key] of numeric) {
    const value = takeValue(flags, flag);
    if (value !== undefined) policy[key] = numberOption('--' + flag, value, key === 'stripComponents' ? 0 : 1);
  }
  const ratio = takeValue(flags, 'max-ratio');
  if (ratio !== undefined) {
    const parsed = Number(ratio);
    if (!Number.isFinite(parsed) || parsed <= 0) usageError('--max-ratio must be a positive finite number');
    policy.maxCompressionRatio = parsed;
  }
  if (takeBoolean(flags, 'allow-symlinks')) policy.allowSymlinks = true;
  if (takeBoolean(flags, 'allow-hardlinks')) policy.allowHardlinks = true;
  if (takeBoolean(flags, 'allow-special-files')) policy.allowSpecialFiles = true;
  if (takeBoolean(flags, 'dry-run')) policy.dryRun = true;
  return policy;
}

function assertNoUnknownFlags(flags) {
  const known = new Set([
    'json',
    'max-bytes',
    'max-compressed-bytes',
    'max-entry-bytes',
    'max-entries',
    'max-ratio',
    'max-depth',
    'max-path-length',
    'strip-components',
    'allow-symlinks',
    'allow-hardlinks',
    'allow-special-files',
    'dry-run',
    'help',
    'version'
  ]);
  for (const key of flags.keys()) {
    if (!known.has(key)) usageError('unknown option --' + key);
  }
}

const TERMINAL_UNSAFE_RE = /[\u0080-\u009f\p{Cf}\u2028\u2029]/u;

function escapeCodePoint(codePoint) {
  if (codePoint <= 0xffff) return '\\u' + codePoint.toString(16).padStart(4, '0');
  const adjusted = codePoint - 0x10000;
  const high = 0xd800 + (adjusted >> 10);
  const low = 0xdc00 + (adjusted & 0x3ff);
  return '\\u' + high.toString(16) + '\\u' + low.toString(16);
}

function escapeTerminalJsonText(text) {
  let output = '';
  for (const character of text) {
    const codePoint = character.codePointAt(0);
    if (TERMINAL_UNSAFE_RE.test(character) || (codePoint >= 0xd800 && codePoint <= 0xdfff)) output += escapeCodePoint(codePoint);
    else output += character;
  }
  return output;
}

function terminalSafe(value) {
  return escapeTerminalJsonText(JSON.stringify(String(value))).slice(1, -1);
}

function printJson(value) {
  process.stdout.write(escapeTerminalJsonText(JSON.stringify(value, null, 2)) + '\n');
}

function printInspection(report) {
  process.stdout.write('safe: ' + (report.safe ? 'yes' : 'no') + '\n');
  process.stdout.write('format: ' + report.format + '\n');
  process.stdout.write('compressed: ' + (report.compressed ? 'yes' : 'no') + '\n');
  process.stdout.write('entries: ' + report.stats.entries + '\n');
  process.stdout.write('uncompressed bytes: ' + report.stats.uncompressedBytes + '\n');
  for (const finding of report.findings) {
    const location = finding.path ? ' at ' + terminalSafe(finding.path) : '';
    process.stdout.write(finding.severity + ': ' + finding.code + location + ': ' + terminalSafe(finding.message) + '\n');
  }
}

async function main(argv) {
  const { positional, flags } = parseArgs(argv);
  assertNoUnknownFlags(flags);
  if (takeBoolean(flags, 'version')) {
    process.stdout.write(TARCAGE_VERSION + '\n');
    return 0;
  }
  if (takeBoolean(flags, 'help') || positional.length === 0) {
    process.stdout.write(HELP);
    return positional.length === 0 && !takeBoolean(flags, 'help') ? 2 : 0;
  }

  const command = positional[0];
  const json = takeBoolean(flags, 'json');
  const policy = policyFromFlags(flags);

  if (command === 'inspect' || command === 'audit') {
    if (positional.length !== 2) usageError(command + ' requires exactly one archive path');
    const report = command === 'inspect' ? await inspectTar(positional[1], policy) : await auditTar(positional[1], policy);
    if (json) printJson(report);
    else printInspection(report);
    return report.safe ? 0 : 1;
  }

  if (command === 'validate') {
    if (positional.length !== 2) usageError('validate requires exactly one archive member path');
    const result = validateTarPath(positional[1], policy);
    if (json) printJson(result);
    else {
      process.stdout.write('valid: ' + (result.valid ? 'yes' : 'no') + '\n');
      if (result.normalized !== null) process.stdout.write('normalized: ' + terminalSafe(result.normalized) + '\n');
      for (const finding of result.findings) process.stdout.write(finding.code + ': ' + terminalSafe(finding.message) + '\n');
    }
    return result.valid ? 0 : 1;
  }

  if (command === 'extract') {
    if (positional.length !== 3) usageError('extract requires an archive path and a destination directory');
    const report = await extractTar(positional[1], positional[2], policy);
    if (json) printJson(report);
    else {
      process.stdout.write('extracted: ' + report.extracted + '\n');
      process.stdout.write('skipped: ' + report.skipped + '\n');
      process.stdout.write('bytes written: ' + report.bytesWritten + '\n');
      process.stdout.write('dry run: ' + (report.dryRun ? 'yes' : 'no') + '\n');
    }
    return 0;
  }

  usageError('unknown command ' + command);
  return 2;
}

try {
  process.exitCode = await main(process.argv.slice(2));
} catch (error) {
  const cliError = error instanceof TarPolicyError || error instanceof TarInputError;
  if (error instanceof TarCageError) {
    process.stderr.write(error.code + ': ' + terminalSafe(error.reason) + '\n');
  } else {
    process.stderr.write('TARCAGE_CLI_ERROR: ' + terminalSafe(error && error.message ? error.message : 'unknown failure') + '\n');
  }
  process.exitCode = cliError ? 2 : 1;
}
