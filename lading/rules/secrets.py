"""Secret rules: does this cargo scatter credentials or reach for key material?"""

from __future__ import annotations

import os
import re

from lading.model import Finding

_HOMEDIR_SECRET = re.compile(
    r"""~?/?(?:\.ssh|\.gnupg|\.aws[/\\]credentials?|\.netrc|\.pypirc|\.docker[/\\]config\.json|\.kube|\.config[/\\]gcloud)
        |(?:ssh-keygen|ssh-copy-id|aws\s+configure|gcloud\s+auth\s+login|docker\s+login|gh\s+auth\s+login)\b""",
    re.IGNORECASE,
)

_ENV_SECRET = re.compile(
    r"""\b(?:export|setenv|set\s+)\s+[A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|APIKEY|AUTH)\b
        |\bos\.environ\[[^\]]+\]
        |(?:dotenv|from_dotenv|load_dotenv|envfile)\s*
        |>>\s*[~]?/?(?:\.env|\.secrets)\b""",
    re.IGNORECASE,
)

# Secret-shaped values: AKIA..., sk-... (OpenAI-style), long hex/b64 blobs, and
# `key = <40+ chars>` assignments. Conservative on purpose.
_AWS_KEY = re.compile(r"""\bAKIA[0-9A-Z]{16}\b|(?:ASIA|AIDA)[0-9A-Z]{16}\b""")
_OPENAI_KEY = re.compile(r"""\b(?:sk|pk)-[A-Za-z0-9_-]{20,}\b""")
_LONG_TOKEN = re.compile(
    r"""(?i)\b(?:api[_-]?key|token|secret|password|passwd)\b[^\n]{0,40}[:=][^\n]{0,60}[A-Za-z0-9_\-./+]{24,}"""
)
_HEX_OR_B64 = re.compile(r"""\b(?:[A-Fa-f0-9]{32,}|[A-Za-z0-9+/]{40,}={0,2})\b""")

# Files whose mere presence is a problem for a skill/agent dir.
_SECRET_FILENAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".netrc",
    ".pypirc",
    ".npmrc",
    ".htpasswd",
}
_SECRET_DIRNAMES = {".ssh", ".gnupg", ".aws", ".kube", ".docker"}


def secret_text_rules(ctx) -> list[Finding]:
    findings: list[Finding] = []
    txt = ctx.text or ""
    rel = ctx.relpath
    if _HOMEDIR_SECRET.search(txt):
        findings.append(
            Finding(
                "SECRET-HOMEDIR",
                "high",
                rel,
                "touches SSH/GnuPG/netrc/AWS credential material or key-generation tools",
            )
        )
    if _ENV_SECRET.search(txt):
        findings.append(Finding("SECRET-ENV", "med", rel, "handles environment secrets (export/environ/dotenv)"))
    if ctx.kind in ("config", "source"):
        if _AWS_KEY.search(txt):
            findings.append(Finding("SECRET-VALUE", "high", rel, "AWS-style access key literal in file"))
        if _OPENAI_KEY.search(txt):
            findings.append(Finding("SECRET-VALUE", "high", rel, "OpenAI-style sk-/pk- token literal in file"))
        m = _LONG_TOKEN.search(txt)
        if m:
            findings.append(Finding("SECRET-VALUE", "med", rel, "assignment looks like a secret value"))
        b = _HEX_OR_B64.search(txt)
        if b and not any(x in (b.group(0) or "") for x in (".git", "/")):
            # hex/b64 blobs that are not git/sha-looking for a *config/source*
            # file are worth a med note.
            findings.append(Finding("SECRET-VALUE", "med", rel, "long hex/base64 blob in config/source"))
    return findings


def secret_fs_rules(root: str) -> list[Finding]:
    """Folder-level check: secret files/dirs present on disk under root."""
    findings: list[Finding] = []
    try:
        entries = os.listdir(root)
    except OSError:
        return findings
    for name in sorted(entries):
        if name in _SECRET_FILENAMES:
            findings.append(
                Finding(
                    "SECRET-FILE-ON-DISK",
                    "med",
                    os.path.join(root, name),
                    "credential-shaped file present in scan root",
                )
            )
        p = os.path.join(root, name)
        if name in _SECRET_DIRNAMES and os.path.isdir(p):
            findings.append(
                Finding(
                    "SECRET-HOMEDIR",
                    "high",
                    os.path.join(root, name),
                    "credential directory present in scan root",
                )
            )
    return findings