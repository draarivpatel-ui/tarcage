# Changelog

All notable changes to this project are documented here. The format uses semantic versioning.

## [1.0.0] - 2026-11-27

### Added

- Initial pure ESM, zero-dependency release.
- Streaming tar and tar.gz inspection for POSIX ustar, PAX, GNU long metadata, and V7-style archives.
- Strict path traversal, symlink, hardlink, typeflag, metadata, checksum, padding, duplicate, collision, terminal-injection, Windows filename, unsupported-extension, gzip-polyglot, and resource-limit defenses.
- Safe extraction with pre-flight validation, root confinement, no overwrite behavior, permission sanitization, deferred directory modes, partial-write completion, dry-run planning, strip-components support, two-pass input verification, and rollback of created objects.
- Typed error hierarchy with stable `TARCAGE_*` codes.
- TypeScript declarations and a cross-platform CLI.
- Explicit Windows-compatible test runner and an eight-job Linux plus Windows CI matrix.
