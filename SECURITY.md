# Security Policy

Report suspected vulnerabilities privately through GitHub Security Advisories for `draarivpatel-ui/tarcage`. Do not open a public issue with exploit details, proof-of-concept archives, or target paths until a maintainer has acknowledged the report.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |
| Older versions | No |

## Scope

In scope:

- CWE-22 archive path traversal or Tar-Slip extraction outside the destination.
- CWE-59 symlink or CWE-61 hardlink confinement failures.
- CWE-409 archive, metadata, or gzip resource-exhaustion bypasses.
- Header checksum, PAX, GNU longname, typeflag, padding, or end-of-archive parsing differentials that change extraction behavior.
- Permission sanitization failures involving setuid, setgid, sticky, or unsafe mode bits.
- Extraction overwrite, rollback, or symlink-on-disk confinement failures.

Out of scope:

- Archives larger than the caller-configured resource limits.
- Operating-system behavior when a user explicitly enables links or special modes.
- Physical filesystem attacks by a process that can modify the destination while extraction is running.
- Denial of service caused by allocating an input buffer that the caller already chose to hold in memory.
- Vulnerabilities in Node.js itself. Those should be reported to the Node.js project.

## Disclosure expectations

Please include the affected version, Node.js version, operating system, a minimal archive generator or hex fixture, the exact policy used, whether the failure occurs in inspection or extraction, and the observed `TARCAGE_*` error code if one exists. A maintainer will triage severity, prepare a regression test, and coordinate disclosure before publishing a fix.
