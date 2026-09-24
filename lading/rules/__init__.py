"""Rule registry. Every rule a `rules` command can enumerate lives here.

Each entry knows which lens it belongs to so `lading rules` can print a
catalog and the engines can say which rules were considered for a lens.
"""

from __future__ import annotations

RULES_DEF: list[dict] = [
    # net.py
    {"id": "NET-PIPE-SH", "sev": "high", "lens": "skill", "catches": "curl/wget/nc | sh — network piped into a shell"},
    {"id": "NET-RAW-URL", "sev": "med", "lens": "skill", "catches": "raw http(s) URL; IP-based endpoints are high"},
    {"id": "NET-JS-FETCH", "sev": "med", "lens": "skill", "catches": "fetch()/WebSocket/XMLHttpRequest in a script or config"},
    {"id": "NET-PY-CLIENT", "sev": "high", "lens": "skill", "catches": "requests/urllib/socket imported by an analyzed script"},
    {"id": "NET-SHELL", "sev": "med", "lens": "skill", "catches": "curl/wget/nc/ssh invocation (fetch utils actually used)"},
    {"id": "NET-FTP", "sev": "med", "lens": "skill", "catches": "ftp:// URL inside a script or config"},
    # secrets.py
    {"id": "SECRET-HOMEDIR", "sev": "high", "lens": "skill", "catches": "writes/reads ~/.ssh, .gnupg, .aws, netrc, or keygen/gcloud/docker login"},
    {"id": "SECRET-ENV", "sev": "med", "lens": "skill", "catches": "env-secret handling: export/env file/dotenv/environ"},
    {"id": "SECRET-VALUE", "sev": "med", "lens": "skill", "catches": "AKIA/sk-/token-shaped literals in config or source text"},
    {"id": "SECRET-FILE-ON-DISK", "sev": "med", "lens": "skill", "catches": ".env/.netrc/etc. present in the scan root"},
    # undeclared.py
    {"id": "UNDECLARED", "sev": "med", "lens": "skill", "catches": "executable in a skill folder not listed in SKILL.md"},
    # repo.py
    {"id": "NO-LOCKFILE", "sev": "high", "lens": "repo", "catches": "no lockfile pinning dependencies"},
    {"id": "README-NO-RUN", "sev": "high", "lens": "repo", "catches": "README missing or documents no runnable command"},
    {"id": "DOTENV-COMMITTED", "sev": "med", "lens": "repo", "catches": ".env committed to the tree (or present, untrackable)"},
    {"id": "NO-TESTS", "sev": "med", "lens": "repo", "catches": "no tests/ directory or test files"},
    {"id": "SECRET-IN-TREE", "sev": "high", "lens": "repo", "catches": "AWS/OpenAI-style token literal in tracked source"},
    # takeout.py
    {"id": "HAS-ATTACHMENT", "sev": "med", "lens": "takeout", "catches": "takeout entry carries an attachment"},
    {"id": "HAS-SYSTEM-PROMPT", "sev": "med", "lens": "takeout", "catches": "takeout entry embeds a system prompt"},
    {"id": "DROPPED-THREAD", "sev": "ok", "lens": "takeout", "catches": "thread/message dropped by --drop filter"},
    {"id": "REDACTED-SECRET", "sev": "ok", "lens": "takeout", "catches": "secret-shaped string redacted in cleaned archive"},
    # mcp / agent lenses reuse the net+secret rules.
    {"id": "MCP-URL", "sev": "med", "lens": "mcp", "catches": "MCP server is a remote URL endpoint"},
    {"id": "MCP-CMD", "sev": "ok", "lens": "mcp", "catches": "MCP server spawns a local command (listed, not executed)"},
    {"id": "AGENT-REF", "sev": "ok", "lens": "agent", "catches": "agent config references a script/tool path"},
]


def rules_by_id() -> dict[str, dict]:
    return {r["id"]: r for r in RULES_DEF}


def rules_for_lens(lens: str) -> list[dict]:
    return [r for r in RULES_DEF if r["lens"] == lens]


def known_rule(rule_id: str) -> bool:
    return rule_id in rules_by_id()