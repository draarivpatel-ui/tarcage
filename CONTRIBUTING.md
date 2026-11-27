# Contributing

## Ground rules

- Keep the package zero-dependency at runtime. Use Node.js built-ins in library code, and keep development dependencies limited to the pinned fast-check property-testing library.
- Keep the library pure ESM. Do not add a transpiler or a generated CommonJS build.
- Preserve fail-closed defaults. Convenience must not weaken validation for untrusted archives.
- Every security behavior needs a deterministic regression test and, where practical, a malformed-archive fixture generated in the test itself.
- Do not commit fixture archives, coverage output, `node_modules`, scratch directories, secrets, local absolute paths, or personally identifying information.
- Use LF line endings. `.gitattributes` enforces this for tracked text files.

## Development

Requires Node 18 or newer.

```sh
node scripts/run-tests.mjs
npm pack --dry-run
```

The test runner intentionally enumerates test files with `fs.readdirSync`; do not replace it with shell glob expansion. Tests that assert POSIX executable bits must guard those assertions with `process.platform !== 'win32'`.

## Security-sensitive changes

Changes to parsing, path validation, link resolution, extraction, limits, rollback, or CLI exit codes require tests for both the malicious and benign case. If a rejection is intentional, document it in `README.md` and name the stable error code in the test.

## Commit style

Keep commits small and focused. Explain why a security rule exists when it is not obvious from the threat model. Do not claim that validation is complete unless the test suite and package dry run have both passed in the same working tree.
