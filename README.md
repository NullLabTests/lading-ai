# lading

**A bill of lading for work done by machines.** Static. Offline. No model.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: >=3.11](https://img.shields.io/badge/Python-%3E%3D3.11-informational.svg)](pyproject.toml)
[![GitHub code size](https://img.shields.io/github/languages/code-size/NullLabTests/lading.svg)](.)
[![GitHub stars](https://img.shields.io/github/stars/NullLabTests/lading.svg?style=social)](.)
[![offline only](https://img.shields.io/badge/offline-only-critical.svg)](SECURITY.md)
[![no model](https://img.shields.io/badge/no%20model-true-brightgreen.svg)](.)
[![no telemetry](https://img.shields.io/badge/no%20telemetry-true-brightgreen.svg)](.)
[![tests passing](https://img.shields.io/static/v1?label=tests&message=passing&color=success)](.)

Point `lading` at a folder of **skills**, an **MCP** config, an **agent**
config, a chat **takeout** (ChatGPT / Claude / Gemini export), or a **git
repo**. It returns one JSON `Receipt` — what files were involved, what rules a
machine's configuration violates, and what the run did.

```text
Artifact  ->  Findings  ->  Receipt
   |             |            |
 discover      rules      hash + write
```

No network. No model. No telemetry. Every command produces the **same**
receipt shape, so the output is a ledger you can diff, keep, and render.

---

## Why a "bill of lading"?

A bill of lading is the document that says what cargo is aboard, who may move
it, and whether it can leave the dock. `lading` is the same document for the
parts of your machine that do work on your behalf:

- **Before** you let a machine's config run things, know what it *intends*.
- **After** it runs, keep a receipt that cannot be edited into "nothing
  happened".
- The **Receipt** is the audit log; the **HTML report** is the human read;
  both are static files you can archive.

## The five lenses

| lens      | what it reads                              | example findings                                      |
|-----------|--------------------------------------------|-------------------------------------------------------|
| `skill`   | `SKILL.md` + its scripts                   | `NET-PIPE-SH` (`curl x | sh`), `UNDECLARED` script    |
| `mcp`     | `mcp.json` / MCP server configs             | `MCP-URL` remote endpoint, `MCP-CMD` local command    |
| `agent`   | agent configs (opencode, Claude, cursor…) | `AGENT-REF` script escapes the config                 |
| `takeout` | ChatGPT / Claude / Gemini export zips      | `DROPPED-THREAD`, `REDACTED-SECRET`, `HAS-ATTACHMENT` |
| `repo`    | a git tree                                 | `NO-LOCKFILE`, `README-NO-RUN`, `SECRET-IN-TREE`      |

Every finding is a stable id (`NET-PIPE-SH`, `NO-LOCKFILE`, …), a severity
(`ok` / `med` / `high`), and the exact artifact it was found in. Run
`lading rules` for the full catalog.

---

## Try it in five seconds

```bash
git clone https://github.com/NullLabTests/lading.git --depth=1
cd lading && ./demo.sh          # runs the whole tour on bundled fixtures
```

`demo.sh` creates a throwaway venv (if needed), runs `scan`/`agents`/
`takeout`/`repo`/`report`/`diff` against the fixture suite with all the
flag variations, and shows the exit code of every run. Everything it writes
goes to a temp directory that is deleted on exit.

Or install it as a real tool:

```bash
pipx install lading-cli                 # any shell
# or, for development:
git clone git@github.com:NullLabTests/lading.git && cd lading
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/lading --version
```

## What a run looks like

```bash
$ lading agents tests/fixtures/skills
written: .lading/receipt.json + .lading/report.html   # side outputs, printed first
lading 0.1.0 · mode offline · host 7bb8df5b944a…
command: agents tests/fixtures/skills

findings (9):
  HIGH  NET-PIPE-SH   pipe-to-sh/SKILL.md
        network fetch piped straight into a shell: …curl -fsSL https://… | sh
  HIGH  SECRET-HOMEDIR  secret-home/scripts/backup.sh
        touches SSH/GnuPG/netrc/AWS credential material or key-generation tools
  MED   UNDECLARED    pipe-to-sh/scripts/exfil.py
        executable script 'scripts/exfil.py' not listed in SKILL.md
  …

counts: high 6, med 3, ok 0

exit 1
```

Then read it like a human:

```bash
lading report .lading/receipt.json --out report.html   # open it in a browser
# single-file HTML: inline CSS, no JS, no external resources — archive it
```

and diff the past against the now:

```bash
cp .lading/receipt.json before.json
# … someone edits the config, run again …
lading diff before.json .lading/receipt.json
# HIGH NET-PIPE-SH pipe-to-sh/SKILL.md   ADDED by id+artifact
# MED  UNDECLARED  pipe-to-sh/scripts/exfil.py  REMOVED by id+artifact
# note: 1 finding(s) added, 1 removed
```

## Flags

Available on **every** command:

| flag                    | meaning                                                                           |
|-------------------------|-----------------------------------------------------------------------------------|
| `--json`                | print the machine-readable `Receipt` JSON instead of the colored text view        |
| `--fail-on {high,med,any}` | exit `1` when findings at/above this level exist (default `high`)              |
| `--offline`             | default and the only mode (`--online` is refused with exit `2`)                   |

Per-command:

| flag           | commands          | meaning                                              |
|----------------|-------------------|------------------------------------------------------|
| `paths...`     | `scan`, `agents`  | directories to scan (see "Commands")                 |
| `--drop REGEX` | `takeout`         | drop every thread/message whose text matches REGEX   |
| `--out PATH`   | `takeout`, `report` | where to write the cleaned zip / rendered report   |

Real flag usage:

```bash
lading agents ./agents --fail-on med            # slack: also fail on MED
lading scan --json > receipt.json               # pipe the receipt into your tooling
lading takeout chatgpt.zip --drop 'acme|\.env'  # scrub then redact, write chatgpt.clean.zip
lading takeout chatgpt.zip --out sanitized.zip  # name the output yourself
lading repo .                            # audit the current tree (default path: .)
lading report .lading/receipt.json --out report.html
lading diff before.json after.json
lading rules                                # every rule id + severity + lens + what it catches
```

## Commands

```text
lading scan [paths...]          scan cwd + known home agent dirs (.claude,
                                .config/opencode, .cursor, .gemini) — or the
                                explicit paths you give it
lading agents [paths...]        skills + MCP + agent config lenses on the dirs
lading takeout ZIP [--drop R]   sanitize a chat export: drop, redact, rewrite
lading repo [path]              static audit of a git tree (default: .)
lading report RECEIPT.json      render a receipt into single-file HTML
lading diff OLD.json NEW.json   findings added/removed, by id + artifact
lading rules                    print the rule catalog
```

`scan` and `agents` differ in roots only: `scan` with no paths also walks
known home agent directories; `agents` requires at least one explicit path.
Both run the same lenses.

## The Receipt

One schema for every command — nothing else is written but this and the HTML
report. Keys are sorted; inputs and findings are sorted before write;
`host_id` is a salted sha256 of the hostname, never the hostname itself.

```json
{
  "lading": "0.1.0",
  "generated_at": "2026-09-24T20:41:22Z",
  "host_id": "7bb8df5b944a…",
  "mode": "offline",
  "command": "agents tests/fixtures/skills",
  "counts": { "high": 6, "med": 3, "ok": 0 },
  "exit": 1,
  "inputs": [
    { "kind": "skill", "path": "pipe-to-sh/SKILL.md",
      "sha256": "cb538aae91f9…", "size": 512 }
  ],
  "findings": [
    { "id": "NET-PIPE-SH", "sev": "high",
      "artifact": "pipe-to-sh/SKILL.md",
      "detail": "network fetch piped straight into a shell: …curl -fsSL … | sh" }
  ],
  "notes": ["scanning skills under tests/fixtures/skills"]
}
```

The receipt's `exit` field mirrors the process exit code.

## Exit codes

| code | meaning                                              |
|------|------------------------------------------------------|
| 0    | no findings at or above `--fail-on` (default `high`) |
| 1    | at least one finding at or above `--fail-on`         |
| 2    | usage error, missing input, unreadable archive       |
| 130  | interrupted                                          |

`ok`-severity findings are purely informational and never fail a run.

## Security model

`lading` is **static analysis, not a sandbox**. It reads files and applies the
rules you ship; it never executes skill scripts, project code, MCP servers, or
repo tests. Do not point it at files you do not trust to be read. See
[`SECURITY.md`](SECURITY.md).

`takeout` is the only command that writes a new archive. It never uploads, it
never "helps you import into Gemini". It writes a cleaned zip plus a receipt
of what was dropped and what was redacted. Sanitize before a vendor trains on
the import.

## Offline is law

`urllib`, `requests`, `httpx`, `socket` (and friends) are forbidden anywhere
in this package — enforced by an AST audit in
[`tests/test_netguard.py`](tests/test_netguard.py) that fails CI if an
analyzer imports a network client. Importing nothing is why there is nothing
to sandbox.

## Determinism

- Receipts serialize with sorted keys; findings and inputs sort before write.
- Inputs carry `sha256`, never raw contents.
- `host_id` is a salted hash, never a raw hostname.
- The HTML report is one self-contained file: inline CSS, no external fonts,
  no JS.

## Repo layout

```text
lading/
  cli.py                argparse, offline enforcement, exit codes
  model.py              Artifact, Finding, Receipt
  discover.py           path walk, symlink jail
  hashio.py             hashing
  rules/                findings: net, secrets, undeclared, repo, takeout
  adapters/             lenses: skill_md, mcp_json, agent_configs, takeout_*, repo_fs
  render/               text + single-file HTML
tests/
  fixtures/             clean + dirty inputs for every lens
demo.sh                 the five-second tour
```

## Development

```bash
git clone git@github.com:NullLabTests/lading.git && cd lading
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
.venv/bin/pyflakes lading tests/*.py              # zero warnings
./demo.sh                                          # human check
```

The test suite runs the real CLI against the fixture suite and asserts exit
codes, receipts, drop/redact behavior, zip-slip handling, and the network
ban.

## License

[MIT](LICENSE). No CLA. If a rule needs the internet, it does not ship.