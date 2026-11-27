# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| < 1.0 | No |

## Reporting a vulnerability

Report suspected vulnerabilities privately through the private GitHub Security Advisories form: [Report a vulnerability](https://github.com/draarivpatel-ui/tarcage/security/advisories/new). Do not open a public issue, pull request, or discussion with exploit details, secrets, private endpoints, or personal data.

Include the affected version, Node.js version, operating system, a minimal archive generator or hex fixture, the exact policy used, whether the failure occurs in inspection or extraction, and the observed `TARCAGE_*` error code if one exists.

## Disclosure timeline

We acknowledge reports within 48 hours. We aim to confirm or reject the report within 7 days, prepare a fix as soon as practical, and coordinate public disclosure with the reporter. Unless a shorter deadline is required by an actively exploited issue, please allow up to 90 days for a coordinated fix and disclosure.

## Scope

In scope:

- CWE-22 archive path traversal or Tar-Slip extraction outside the destination
- CWE-59 symlink or CWE-61 hardlink confinement failures
- CWE-409 archive, metadata, or gzip resource-exhaustion bypasses
- Header checksum, PAX, GNU longname, typeflag, padding, or end-of-archive parsing differentials that change extraction behavior
- Permission sanitization failures involving setuid, setgid, sticky, or unsafe mode bits
- Extraction overwrite, rollback, or symlink-on-disk confinement failures

## Out of scope

Archives larger than caller-configured resource limits, operating-system behavior after a user explicitly enables links or special modes, physical filesystem attacks by a process that can modify the destination while extraction is running, and vulnerabilities in Node.js itself are out of scope.

## Hardening notes

The package has zero runtime dependencies. Input budgets, fail-closed validation, deterministic tests, and property-based fuzz tests are part of the maintenance bar. A report that the library marks unsafe must block the operation in the caller; audit output is a boundary signal, not proof that a downstream system is safe.

## Disclosure history

No published advisories yet. Fixed versions will be listed here with their advisory links.
