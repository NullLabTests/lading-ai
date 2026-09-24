# Security

## What lading is

`lading` is a static analysis tool. It reads files on disk (skills, MCP
configs, agent configs, chat takeouts, source trees) and applies deterministic
rules to them. The result is a JSON receipt plus, for `takeout`, a cleaned
archive.

`lading` is **not a sandbox**. It does not sandbox, jail or isolate anything
but the outcome of its own analysis. It never:

- executes skill scripts, project code, MCP servers, or repo tests;
- connects to any network endpoint;
- contacts any model service;
- uploads or transmits takeout data.

If you point `lading` at a file, `lading` reads that file. That is the extent
of its guarantee. Do not point it at data you do not want read, and do not
scan directories that contain files you cannot afford to have hashed.

## Offline enforcement

The package must never import `urllib`, `requests`, `httpx`, or open a socket
to anything but localhost in tests. `tests/test_netguard.py` statically audits
every lading module with an AST walk and fails CI on a violation. There is no
`--online` escape hatch; the `--online` flag is refused with a usage error.

## Takeout handling

`lading takeout` unzips nothing to disk by default; entries are read in
memory. The in-memory extractor applies a zip-slip guard: any entry whose
resolved path would escape the extraction root is rejected, and `lading
takeout` refuses to write a cleaned archive containing such an entry. New
archives are always written from scratch with clean paths. Attachments and
metadata are inspected for secret-shaped strings and redacted before the
cleaned archive is written.

## Secrets

Receipts record *that* input files were hashed and *whether* secret-shaped
strings were found or redacted — never the secret values themselves. Drop and
redact actions are reported as counts plus the thread/file affected, with the
matching content replaced by `[REDACTED]` in the output archive only.

## Rules are opinionated, not a guarantee

Findings are heuristic. A rule that finds no match does not prove a skill is
harmless, a repo is reproducible, or a takeout is clean. Treat lading output
as a bill of lading — a manifest of observed cargo — not as a certificate of
safety.

## Reporting vulnerabilities

This project has no network channel by design. Report issues by opening an
issue on the source repository (if one exists for your copy), or contact the
maintainer who gave you this tree.