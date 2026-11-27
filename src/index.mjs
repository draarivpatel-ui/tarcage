export const TARCAGE_VERSION = '1.0.0';

export {
  TARCAGE_ERROR_CODES,
  TarCageError,
  TarInputError,
  TarPolicyError,
  TarFormatError,
  TarChecksumError,
  TarPathError,
  TarLinkError,
  TarLimitError,
  TarExtractionError,
  TarCliError
} from './errors.mjs';

export { DEFAULT_TAR_POLICY, createTarPolicy, sanitizeMode } from './policy.mjs';
export {
  validateTarPath,
  assertValidTarPath,
  collisionKey,
  validateSymlinkTarget,
  validateHardlinkTarget,
  resolveSymlinkWithinRoot,
  resolveRootRelativeWithinRoot
} from './path-security.mjs';
export { inspectTar, auditTar, parseTar, listTarEntries } from './api.mjs';
export { extractTar } from './extract.mjs';
