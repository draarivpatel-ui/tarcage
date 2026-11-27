import { TARCAGE_ERROR_CODES as C, TarPolicyError } from './errors.mjs';

const MiB = 1024 * 1024;

export const DEFAULT_TAR_POLICY = Object.freeze({
  compressed: 'auto',
  strictEof: true,
  strictChecksum: true,
  strictPadding: true,
  allowSignedChecksums: false,
  allowSymlinks: false,
  allowHardlinks: false,
  allowSpecialFiles: false,
  allowContiguousFiles: false,
  allowSpecialModes: false,
  rejectDuplicates: true,
  rejectCaseCollisions: true,
  maxCompressedBytes: 128 * MiB,
  maxUncompressedBytes: 256 * MiB,
  maxEntryBytes: 64 * MiB,
  maxEntries: 4096,
  maxDepth: 32,
  maxPathLength: 1024,
  maxComponentLength: 255,
  maxCompressionRatio: 100,
  maxMetadataBytes: MiB,
  maxMetadataEntries: 1024,
  maxSymlinkDepth: 16,
  stripComponents: 0,
  umask: 0o022,
  dryRun: false
});

const BOOLEAN_KEYS = new Set([
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
]);

const POSITIVE_INTEGER_KEYS = new Set([
  'maxCompressedBytes',
  'maxUncompressedBytes',
  'maxEntryBytes',
  'maxEntries',
  'maxDepth',
  'maxPathLength',
  'maxComponentLength',
  'maxMetadataBytes',
  'maxMetadataEntries',
  'maxSymlinkDepth'
]);

const NON_NEGATIVE_INTEGER_KEYS = new Set(['stripComponents']);
const KNOWN_KEYS = new Set([
  ...Object.keys(DEFAULT_TAR_POLICY)
]);

function policyError(reason, key, value) {
  throw new TarPolicyError(C.INVALID_OPTIONS, reason, { key, value });
}

function assertBoolean(key, value) {
  if (typeof value !== 'boolean') policyError(key + ' must be a boolean', key, value);
  return value;
}

function assertPositiveInteger(key, value) {
  if (!Number.isSafeInteger(value) || value < 1) {
    policyError(key + ' must be a positive safe integer', key, value);
  }
  return value;
}

function assertNonNegativeInteger(key, value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    policyError(key + ' must be a non-negative safe integer', key, value);
  }
  return value;
}

export function createTarPolicy(options = {}) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    policyError('options must be an object', 'options', options);
  }

  const output = { ...DEFAULT_TAR_POLICY };
  for (const [key, value] of Object.entries(options)) {
    if (!KNOWN_KEYS.has(key)) policyError('unknown option', key, value);
    if (BOOLEAN_KEYS.has(key)) {
      output[key] = assertBoolean(key, value);
    } else if (POSITIVE_INTEGER_KEYS.has(key)) {
      output[key] = assertPositiveInteger(key, value);
    } else if (NON_NEGATIVE_INTEGER_KEYS.has(key)) {
      output[key] = assertNonNegativeInteger(key, value);
    } else if (key === 'maxCompressionRatio') {
      if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
        policyError('maxCompressionRatio must be a positive finite number', key, value);
      }
      output[key] = value;
    } else if (key === 'umask') {
      if (!Number.isSafeInteger(value) || value < 0 || value > 0o777) {
        policyError('umask must be an integer between 0 and 0o777', key, value);
      }
      output[key] = value;
    } else if (key === 'compressed') {
      if (value !== 'auto' && typeof value !== 'boolean') {
        policyError('compressed must be true, false, or auto', key, value);
      }
      output[key] = value;
    }
  }

  if (output.maxCompressedBytes > Number.MAX_SAFE_INTEGER || output.maxUncompressedBytes > Number.MAX_SAFE_INTEGER) {
    policyError('byte limits must stay within the safe integer range', 'maxUncompressedBytes', output.maxUncompressedBytes);
  }

  return Object.freeze(output);
}

export function sanitizeMode(rawMode, type, policy) {
  const fallback = type === 'directory' ? 0o755 : 0o644;
  const numeric = Number.isSafeInteger(rawMode) ? rawMode : fallback;
  const permissionBits = policy.allowSpecialModes ? numeric & 0o7777 : numeric & 0o777;
  const effective = permissionBits === 0 ? fallback : permissionBits;
  return (effective & ~policy.umask) >>> 0;
}

export function publicPolicy(policy) {
  return Object.freeze({ ...policy });
}
