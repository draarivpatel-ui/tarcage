export const TARCAGE_ERROR_CODES = Object.freeze({
  INVALID_INPUT: 'TARCAGE_INVALID_INPUT',
  INVALID_OPTIONS: 'TARCAGE_INVALID_OPTIONS',
  INPUT_IO: 'TARCAGE_INPUT_IO',
  GZIP_ERROR: 'TARCAGE_GZIP_ERROR',
  COMPRESSED_LIMIT: 'TARCAGE_COMPRESSED_LIMIT',
  UNCOMPRESSED_LIMIT: 'TARCAGE_UNCOMPRESSED_LIMIT',
  RATIO_LIMIT: 'TARCAGE_RATIO_LIMIT',
  MALFORMED_ARCHIVE: 'TARCAGE_MALFORMED_ARCHIVE',
  TRUNCATED_ARCHIVE: 'TARCAGE_TRUNCATED_ARCHIVE',
  EOF_MISSING: 'TARCAGE_EOF_MISSING',
  TRAILING_DATA: 'TARCAGE_TRAILING_DATA',
  PADDING_CORRUPT: 'TARCAGE_PADDING_CORRUPT',
  CHECKSUM_MISMATCH: 'TARCAGE_CHECKSUM_MISMATCH',
  NUMERIC_FIELD: 'TARCAGE_NUMERIC_FIELD',
  INVALID_ENCODING: 'TARCAGE_INVALID_ENCODING',
  UNSUPPORTED_TYPEFLAG: 'TARCAGE_UNSUPPORTED_TYPEFLAG',
  SPECIAL_FILE: 'TARCAGE_SPECIAL_FILE',
  PAX_FORMAT: 'TARCAGE_PAX_FORMAT',
  PAX_CONFLICT: 'TARCAGE_PAX_CONFLICT',
  GNU_METADATA: 'TARCAGE_GNU_METADATA',
  METADATA_LIMIT: 'TARCAGE_METADATA_LIMIT',
  ENTRY_LIMIT: 'TARCAGE_ENTRY_LIMIT',
  ENTRY_SIZE_LIMIT: 'TARCAGE_ENTRY_SIZE_LIMIT',
  PATH_EMPTY: 'TARCAGE_PATH_EMPTY',
  PATH_TOO_LONG: 'TARCAGE_PATH_TOO_LONG',
  PATH_TOO_DEEP: 'TARCAGE_PATH_TOO_DEEP',
  COMPONENT_TOO_LONG: 'TARCAGE_COMPONENT_TOO_LONG',
  CONTROL_CHARACTER: 'TARCAGE_CONTROL_CHARACTER',
  PATH_TRAVERSAL: 'TARCAGE_PATH_TRAVERSAL',
  ABSOLUTE_PATH: 'TARCAGE_ABSOLUTE_PATH',
  DRIVE_PATH: 'TARCAGE_DRIVE_PATH',
  UNC_PATH: 'TARCAGE_UNC_PATH',
  BACKSLASH_SEPARATOR: 'TARCAGE_BACKSLASH_SEPARATOR',
  EMPTY_PATH_SEGMENT: 'TARCAGE_EMPTY_PATH_SEGMENT',
  RESERVED_NAME: 'TARCAGE_RESERVED_NAME',
  TRAILING_DOT_OR_SPACE: 'TARCAGE_TRAILING_DOT_OR_SPACE',
  WINDOWS_INVALID_CHARACTER: 'TARCAGE_WINDOWS_INVALID_CHARACTER',
  UNSUPPORTED_EXTENSION: 'TARCAGE_UNSUPPORTED_EXTENSION',
  DUPLICATE_PATH: 'TARCAGE_DUPLICATE_PATH',
  CASE_COLLISION: 'TARCAGE_CASE_COLLISION',
  OVERLAPPING_ENTRIES: 'TARCAGE_OVERLAPPING_ENTRIES',
  SYMLINK_BLOCKED: 'TARCAGE_SYMLINK_BLOCKED',
  HARDLINK_BLOCKED: 'TARCAGE_HARDLINK_BLOCKED',
  LINK_INVALID: 'TARCAGE_LINK_INVALID',
  LINK_ESCAPE: 'TARCAGE_LINK_ESCAPE',
  LINK_CHAIN: 'TARCAGE_LINK_CHAIN',
  MODE_STRIPPED: 'TARCAGE_MODE_STRIPPED',
  EXTRACTION_REFUSED: 'TARCAGE_EXTRACTION_REFUSED',
  EXTRACTION_SYMLINK: 'TARCAGE_EXTRACTION_SYMLINK',
  EXTRACTION_CONFINEMENT: 'TARCAGE_EXTRACTION_CONFINEMENT',
  EXTRACTION_OVERWRITE: 'TARCAGE_EXTRACTION_OVERWRITE',
  EXTRACTION_IO: 'TARCAGE_EXTRACTION_IO',
  INPUT_CHANGED: 'TARCAGE_INPUT_CHANGED',
  CLI_USAGE: 'TARCAGE_CLI_USAGE'
});

export class TarCageError extends Error {
  constructor(code, message, details, cause) {
    super(code + ': ' + message);
    this.name = 'TarCageError';
    this.code = code;
    this.reason = message;
    if (details !== undefined) this.details = details;
    if (cause !== undefined) this.cause = cause;
  }

  toJSON() {
    return {
      name: this.name,
      code: this.code,
      reason: this.reason,
      details: this.details
    };
  }
}

function makeSubclass(name) {
  return class extends TarCageError {
    constructor(code, message, details, cause) {
      super(code, message, details, cause);
      this.name = name;
    }
  };
}

export const TarInputError = makeSubclass('TarInputError');
export const TarPolicyError = makeSubclass('TarPolicyError');
export const TarFormatError = makeSubclass('TarFormatError');
export const TarChecksumError = makeSubclass('TarChecksumError');
export const TarPathError = makeSubclass('TarPathError');
export const TarLinkError = makeSubclass('TarLinkError');
export const TarLimitError = makeSubclass('TarLimitError');
export const TarExtractionError = makeSubclass('TarExtractionError');
export const TarCliError = makeSubclass('TarCliError');

export function errorFinding(error, severity = 'fatal') {
  if (error instanceof TarCageError) {
    return {
      severity,
      code: error.code,
      message: error.reason,
      path: error.details && typeof error.details.path === 'string' ? error.details.path : null,
      offset: error.details && Number.isSafeInteger(error.details.offset) ? error.details.offset : null
    };
  }
  return {
    severity,
    code: TARCAGE_ERROR_CODES.MALFORMED_ARCHIVE,
    message: error && error.message ? error.message : 'unknown archive failure',
    path: null,
    offset: null
  };
}
