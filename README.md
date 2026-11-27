# tarcage

`tarcage` is a zero-dependency Node.js library for inspecting, auditing, and safely extracting tar archives. It parses POSIX ustar, PAX extended headers, GNU long names and links, and old V7-style headers. It accepts plain `.tar` data and gzip-compressed `.tar.gz` or `.tgz` data from a `Buffer`, `Uint8Array`, or file path.

The package is pure ESM, uses only Node.js built-ins, and supports Node 18 or newer.

## Security model

The default policy is fail-closed. It is designed for untrusted archives and blocks or limits the following attack classes:

- Tar-Slip and path traversal, including CVE-2007-4559 style extraction outside the destination, CWE-22 absolute paths, drive paths, UNC paths, parent traversal, backslash separators, NUL bytes, control characters, bidi controls, Unicode format characters, line separators, unpaired surrogates, Windows device names, Windows-invalid filename characters and alternate data stream syntax, trailing dots or spaces, overlong paths, excessive depth, duplicate entries, overlapping entries, and case-insensitive collisions.
- Symlink and hardlink escape, CWE-59 and CWE-61. Links are blocked by default. When explicitly enabled, targets are resolved lexically inside the extraction root, chained links are checked, cycles are rejected, pre-existing disk symlinks are never followed, and every parent directory is checked with `lstat` plus a realpath root-boundary test.
- Special files and unsafe permission bits. Character devices, block devices, FIFOs, contiguous entries, and unknown typeflags are blocked by default. Setuid, setgid, and sticky bits are stripped unless explicitly enabled. Extraction never creates device nodes or FIFOs.
- Header spoofing and parser differentials. Header checksums are verified, legacy signed checksums are rejected unless explicitly enabled, numeric fields reject negative and overflowing values, PAX records are strictly length checked, duplicate PAX and GNU metadata are rejected, conflicting `path`, `linkpath`, and `size` values are rejected, semantic PAX extensions for sparse or incremental extraction fail closed, entry padding must be zero, and `strictEof` detects missing end blocks, trailing non-zero tar data, or unread bytes after the final gzip member.
- Tar and gzip resource exhaustion, CWE-409. Limits cover compressed input bytes, uncompressed archive bytes, individual entry bytes, entry count, path depth, path length, metadata bytes, metadata count, compression ratio, and symlink chain depth. Gzip input is decompressed as a stream, so a bomb is rejected while data is flowing rather than after buffering the whole expanded payload.

Inspection is non-executable and does not write files. Extraction performs a complete pre-flight pass before writing. It never overwrites existing filesystem objects. If extraction fails after writing begins, files, links, and directories created by that extraction are removed in reverse order.

## Install

```sh
npm install tarcage
```

## Quick start

```js
import { inspectTar, extractTar } from 'tarcage';

const report = await inspectTar('release.tar.gz');
if (!report.safe) {
  console.error(report.findings);
  process.exit(1);
}

await extractTar('release.tar.gz', 'unpackaged-release');
```

## API

### `inspectTar(input, options)`

Returns a structured report and does not throw for archive-format violations. Input or option errors still throw.

```js
const report = await inspectTar(buffer);
console.log(report.safe, report.format, report.stats, report.findings);
```

The report contains:

- `safe`: `true` when no fatal finding was detected under the active policy.
- `format`: `pax`, `gnu`, `ustar`, `v7`, or `unknown`.
- `compressed`: whether gzip compression was detected or selected.
- `entries`: normalized entry metadata, not file contents.
- `findings`: fatal and warning findings with stable `TARCAGE_*` codes.
- `stats`: byte, entry, metadata, depth, checksum, and compression-ratio counters.

### `auditTar(input, options)`

Returns the inspection report plus the active policy, a plain `safe` or `unsafe` verdict, and conservative recommendations. It is intended for archive review tools and CI gates.

### `parseTar(input, options)`

Strictly parses the archive and returns entries plus statistics. Unlike `inspectTar`, the first fatal archive violation throws a typed error.

### `listTarEntries(input, options)`

Strictly parses and returns only the entry array.

### `extractTar(input, destDir, options)`

Safely extracts after a complete pre-flight validation pass. The extractor:

1. Validates every entry, link graph, path collision, metadata block, size limit, checksum, and archive terminator before writing.
2. Re-reads the input and compares the uncompressed SHA-256 from both passes, rolling back if the input changed.
3. Creates no overwrite of any existing file, symlink, directory, FIFO, socket, or device.
4. Creates parent directories without following pre-existing symlinks.
5. Applies sanitized file modes and the configured policy umask. Directory modes are deferred until all child entries have been written.
6. Restores write access to directories it created before rollback, then removes only filesystem objects created by the current extraction if failure occurs.

`dryRun: true` validates and reports the extraction plan without touching the destination. `stripComponents` removes leading archive path components before extraction. Stripping is validated again because it can change collision and symlink semantics.

### `validateTarPath(entryPath, options)`

Validates one archive member path without parsing an archive. It returns `{ valid, normalized, depth, hadTrailingSlash, findings }` instead of throwing for path violations.

### `createTarPolicy(options)`

Validates and freezes a reusable policy object. Unknown options, wrong types, invalid ranges, and inconsistent values throw `TarPolicyError` with `TARCAGE_INVALID_OPTIONS`.

## Important defaults

```js
{
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
  maxCompressedBytes: 134217728,
  maxUncompressedBytes: 268435456,
  maxEntryBytes: 67108864,
  maxEntries: 4096,
  maxDepth: 32,
  maxPathLength: 1024,
  maxComponentLength: 255,
  maxCompressionRatio: 100,
  maxMetadataBytes: 1048576,
  maxMetadataEntries: 1024,
  maxSymlinkDepth: 16,
  stripComponents: 0,
  umask: 0o022,
  dryRun: false
}
```

Compression-ratio checking starts after one MiB of uncompressed output. This prevents tiny gzip headers and mostly zero end blocks from creating false positives, while a streaming bomb is still stopped long before the uncompressed byte cap.

## Links

Symlinks and hardlinks are blocked unless explicitly enabled:

```js
await extractTar(input, dest, {
  allowSymlinks: true,
  allowHardlinks: true
});
```

Even then, absolute targets, drive or UNC targets, backslashes, control characters, root escapes, cyclic chains, excessive chains, and paths traversing a symlinked directory are rejected. Symlink targets are interpreted relative to the containing archive directory. Hardlink targets are interpreted relative to the archive root. Special files can be inspected when `allowSpecialFiles` is true, but extraction always refuses to create them.

## PAX and GNU strictness

PAX records are parsed using their self-delimited decimal lengths. malformed lengths, missing newlines, duplicate keys, forbidden keys, invalid UTF-8, and security-sensitive global overrides are fatal. A PAX `size` must agree exactly with the ustar size field. A PAX `path` or `linkpath` must either agree with the header, represent a plausible long-name completion of the header, or be the only usable representation. GNU longname and longlink values must be NUL-terminated and conflict-free when combined with PAX metadata.

This strictness intentionally rejects some producer-specific archives that rely on ambiguous metadata. The purpose is to prevent one parser from seeing a safe entry while another parser sees a different path, link, or size.

Unsigned checksums are required by default. Some legacy tar writers produced signed checksums. They can be accepted with `allowSignedChecksums: true`; accepted legacy checksums are reported as warnings. `strictChecksum: false` disables checksum verification and should only be used for format research, not untrusted input.

## CLI

```sh
tarcage inspect archive.tar.gz
tarcage audit archive.tar --json
tarcage validate member/path.txt
tarcage extract archive.tar.gz output-directory --max-entries 1000
```

Useful limits and extraction flags:

```sh
tarcage inspect archive.tgz --max-bytes 100000000 --max-ratio 50 --json
tarcage extract archive.tar out --strip-components 1 --dry-run
tarcage extract archive.tar out --allow-symlinks --allow-hardlinks
```

Exit codes:

- `0`: safe under the active policy.
- `1`: unsafe findings or extraction refusal.
- `2`: command-line usage, invalid options, or input-file errors.

## Examples

Runnable examples are in `examples/`:

```sh
node examples/inspect.mjs archive.tar.gz
node examples/extract.mjs archive.tar.gz output-directory
node examples/policy.mjs
```

## TypeScript

Types are included in `types/index.d.ts` and are wired through the package `exports` map. The library is pure ESM:

```ts
import { inspectTar, type TarInspectReport } from 'tarcage';
const report: TarInspectReport = await inspectTar(input);
```

## Testing

```sh
node scripts/run-tests.mjs
```

The verified local release suite contains 673 deterministic tests.

The runner explicitly enumerates `tests/*.test.mjs` with `fs.readdirSync` and passes exact file paths to `node --test`. It does not depend on shell glob expansion, so the same command works on Linux, macOS, and Windows.

## Limitations

- Sparse files, multi-volume archives, incremental GNU metadata, Solaris filetype extensions, and vendor-specific typeflags are rejected instead of being extracted with incompatible regular-file semantics.
- PAX extension keys other than `path`, `linkpath`, and `size` are parsed and exposed in entry metadata but do not alter extraction behavior.
- File data is streamed during extraction, but archive metadata and the entry list are retained in memory up to `maxEntries`.
- The uncompressed SHA-256 two-pass check detects input replacement between validation and extraction. It does not make a path input immutable, so callers handling hostile local writers should pass a stable `Buffer` or protect the file themselves.
- Rollback removes only objects created by the current extraction. A destination that already contains unrelated files is left otherwise unchanged.
- On Windows, symlink creation can require additional operating-system privileges. Validation still works, but creating links can fail at the operating-system boundary.
- POSIX modes cannot be represented exactly on Windows. Mode assertions in the test suite are guarded for that platform.

## Error handling

All library-generated errors inherit from `TarCageError` and expose a stable `code` beginning with `TARCAGE_`. More specific classes include `TarFormatError`, `TarChecksumError`, `TarPathError`, `TarLinkError`, `TarLimitError`, `TarInputError`, `TarPolicyError`, and `TarExtractionError`.

```js
import { parseTar, TarCageError } from 'tarcage';

try {
  await parseTar(input);
} catch (error) {
  if (error instanceof TarCageError) console.error(error.code, error.details);
  else throw error;
}
```

## License

MIT. See `LICENSE`.
