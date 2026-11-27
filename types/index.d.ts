/// <reference types="node" />

export const TARCAGE_VERSION: string;

export type TarInput = Buffer | Uint8Array | string;
export type CompressionOption = boolean | 'auto';
export type TarEntryType =
  | 'file'
  | 'directory'
  | 'symlink'
  | 'hardlink'
  | 'character-device'
  | 'block-device'
  | 'fifo';
export type TarFormat = 'pax' | 'gnu' | 'ustar' | 'v7' | 'unknown';
export type FindingSeverity = 'fatal' | 'warning' | 'info';

export interface TarPolicyOptions {
  compressed?: CompressionOption;
  strictEof?: boolean;
  strictChecksum?: boolean;
  strictPadding?: boolean;
  allowSignedChecksums?: boolean;
  allowSymlinks?: boolean;
  allowHardlinks?: boolean;
  allowSpecialFiles?: boolean;
  allowContiguousFiles?: boolean;
  allowSpecialModes?: boolean;
  rejectDuplicates?: boolean;
  rejectCaseCollisions?: boolean;
  maxCompressedBytes?: number;
  maxUncompressedBytes?: number;
  maxEntryBytes?: number;
  maxEntries?: number;
  maxDepth?: number;
  maxPathLength?: number;
  maxComponentLength?: number;
  maxCompressionRatio?: number;
  maxMetadataBytes?: number;
  maxMetadataEntries?: number;
  maxSymlinkDepth?: number;
  stripComponents?: number;
  umask?: number;
  dryRun?: boolean;
}

export interface TarPolicy extends Required<TarPolicyOptions> {}

export interface TarFinding {
  severity: FindingSeverity;
  code: string;
  message: string;
  path: string | null;
  offset: number | null;
}

export interface TarEntry {
  index: number;
  name: string;
  type: TarEntryType;
  size: number;
  mode: number;
  rawMode: number;
  mtime: number;
  uid: number;
  gid: number;
  uname: string;
  gname: string;
  linkname: string;
  offset: number;
  headerFormat: 'ustar' | 'gnu' | 'v7';
  contiguous: boolean;
  pax: Record<string, string>;
}

export interface TarStats {
  entries: number;
  files: number;
  directories: number;
  symlinks: number;
  hardlinks: number;
  special: number;
  compressedBytes: number;
  uncompressedBytes: number;
  totalEntryBytes: number;
  maxDepth: number;
  metadataBytes: number;
  metadataEntries: number;
  endMarkers: number;
  compressionRatio: number | null;
  uncompressedSha256: string | null;
}

export interface TarParseResult {
  format: TarFormat;
  compressed: boolean;
  entries: TarEntry[];
  findings: TarFinding[];
  stats: TarStats;
}

export interface TarInspectReport extends TarParseResult {
  safe: boolean;
}

export interface TarAuditReport extends TarInspectReport {
  verdict: 'safe' | 'unsafe';
  policy: TarPolicy;
  recommendations: string[];
}

export interface TarValidationResult {
  valid: boolean;
  normalized: string | null;
  depth: number;
  hadTrailingSlash: boolean;
  findings: TarFinding[];
}

export interface TarExtractReport {
  dryRun: boolean;
  destDir: string;
  extracted: number;
  skipped: number;
  files: number;
  directories: number;
  symlinks: number;
  hardlinks: number;
  bytesWritten: number;
  uncompressedSha256: string | null;
}

export interface TarDryRunReport extends TarExtractReport {
  dryRun: true;
  bytesPlanned: number;
}

export const TARCAGE_ERROR_CODES: Readonly<Record<string, string>>;
export const DEFAULT_TAR_POLICY: Readonly<TarPolicy>;

export class TarCageError extends Error {
  constructor(code: string, message: string, details?: unknown, cause?: unknown);
  code: string;
  reason: string;
  details?: unknown;
  toJSON(): { name: string; code: string; reason: string; details?: unknown };
}

export class TarInputError extends TarCageError {}
export class TarPolicyError extends TarCageError {}
export class TarFormatError extends TarCageError {}
export class TarChecksumError extends TarCageError {}
export class TarPathError extends TarCageError {}
export class TarLinkError extends TarCageError {}
export class TarLimitError extends TarCageError {}
export class TarExtractionError extends TarCageError {}
export class TarCliError extends TarCageError {}

export function createTarPolicy(options?: TarPolicyOptions): Readonly<TarPolicy>;
export function sanitizeMode(rawMode: number, type: string, policy: Readonly<TarPolicy>): number;
export function validateTarPath(entryPath: string, options?: TarPolicyOptions): TarValidationResult;
export function assertValidTarPath(entryPath: string, policy: Readonly<TarPolicy>): TarValidationResult;
export function collisionKey(value: string): string;
export function validateSymlinkTarget(entryName: string, target: string, policy: Readonly<TarPolicy>): string;
export function validateHardlinkTarget(entryName: string, target: string, policy: Readonly<TarPolicy>): string;
export function resolveSymlinkWithinRoot(
  entryName: string,
  target: string,
  symlinkMap: ReadonlyMap<string, string>,
  policy: Readonly<TarPolicy>
): string;
export function resolveRootRelativeWithinRoot(
  target: string,
  symlinkMap: ReadonlyMap<string, string>,
  policy: Readonly<TarPolicy>
): string;
export function inspectTar(input: TarInput, options?: TarPolicyOptions): Promise<TarInspectReport>;
export function auditTar(input: TarInput, options?: TarPolicyOptions): Promise<TarAuditReport>;
export function parseTar(input: TarInput, options?: TarPolicyOptions): Promise<TarParseResult>;
export function listTarEntries(input: TarInput, options?: TarPolicyOptions): Promise<TarEntry[]>;
export function extractTar(input: TarInput, destDir: string, options?: TarPolicyOptions): Promise<TarExtractReport | TarDryRunReport>;
