from __future__ import annotations

import os
import re

from lading.model import Finding

_LOCKFILES = [
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
    "poetry.lock",
    "Pipfile.lock",
    "requirements.txt",
    "uv.lock",
    "Cargo.lock",
    "go.sum",
    "go.mod",
    "composer.lock",
    "Gemfile.lock",
    "flake.lock",
    "Cargo.lock",
    "vendor/modules.txt",
]

_README_NAMES = re.compile(r"(?i)^(readme|readme\.md|readme\.rst|readme\.txt)$")
_RUN_HINTS = re.compile(
    "npm\\s+run|npm\\s+(start|test|dev|build)|yarn\\s+(start|test|dev)|pnpm\\s+|python\\s+-m"
    "|pytest|uv\\s+run|poetry\\s+run|cargo\\s+(run|test|build)|go\\s+(run|test)|make\\s+[a-z]"
    "|just\\s+[a-z]|pipx\\s+run|nox|tox|gradle\\s+(run|test)|cargo install|uv\\s+tool"
    "|\\b(npm|yarn|pnpm|pipx)\\s+(install|add)\\b|usage:|getting\\s+started|quickstart|how to run"
    "|\\b(run|test|build)\\s+it\\b|\\bclick\\s+run\\b",
    re.IGNORECASE,
)


def repo_rules(ctx) -> list[Finding]:
    """ctx: object with .root, .files (abs paths), .is_git, .tracked set, .notes.

    Static only. Never executes anything in the repo.
    """
    findings: list[Finding] = []
    seen_locks = [f for f in ctx.files if os.path.basename(f).lower() in _LOCKFILES]
    if not seen_locks:
        findings.append(
            Finding("NO-LOCKFILE", "high", ctx.root + "/", "no lock/manifest pinning dependencies in repo")
        )

    readme = _find_readme(ctx.files)
    if readme is None:
        findings.append(Finding("README-NO-RUN", "high", ctx.root + "/", "no README found; repo cannot be run as documented"))
    else:
        try:
            with open(readme, "r", errors="replace") as f:
                body = f.read()
        except OSError:
            body = ""
        if not _RUN_HINTS.search(body):
            findings.append(Finding("README-NO-RUN", "high", os.path.relpath(readme, ctx.root), "README present but documents no runnable command"))

    env_files = [f for f in ctx.files if os.path.basename(f) in (".env", ".env.local", ".env.development", ".env.production", ".env.test")]
    for ef in sorted(env_files):
        shown = os.path.relpath(ef, ctx.root)
        if ctx.is_git:
            if ef in ctx.tracked:
                findings.append(Finding("DOTENV-COMMITTED", "med", shown, ".env tracked in git — secrets would ship with the tree"))
        else:
            findings.append(Finding("DOTENV-COMMITTED", "med", shown, ".env on disk (no git metadata to confirm tracking)"))

    has_tests = any(
        os.path.relpath(f, ctx.root).replace(os.sep, "/").lstrip("/").startswith(("tests/", "test/"))
        or os.path.basename(f) in ("test_main.py",) or ("test_" in os.path.basename(f) and f.endswith(".py"))
        for f in ctx.files
    )
    if not has_tests:
        findings.append(Finding("NO-TESTS", "med", ctx.root + "/", "no tests/ directory or test files found"))

    _secret_in_tree(ctx, findings)

    return findings


def _find_readme(files: list[str]) -> str | None:
    for f in files:
        if _README_NAMES.search(os.path.basename(f)):
            return f
    return None


def _secret_in_tree(ctx, findings: list[Finding]) -> None:
    from lading.rules.secrets import _AWS_KEY, _OPENAI_KEY

    scanned = 0
    for f in sorted(ctx.files):
        base = os.path.basename(f)
        if base.endswith((".pyc", ".pyo", ".so", ".dll", ".exe", ".bin", ".png", ".jpg", ".gif", ".zip", ".whl", ".lock")):
            continue
        rel = os.path.relpath(f, ctx.root)
        rel = rel.replace(os.sep, "/")
        if rel.startswith(".git/") or rel.startswith("tests/") or rel.startswith("fixtures/"):
            continue
        if ctx.is_git and f not in ctx.tracked:
            continue  # untracked files don't ship; but .env meds already cover disk presence
        if scanned >= 400:
            break
        try:
            with open(f, "r", errors="replace") as fh:
                head = fh.read(65536)
        except OSError:
            continue
        if not head[:10].isprintable():
            continue
        scanned += 1
        hak = _AWS_KEY.search(head)
        if hak:
            findings.append(Finding("SECRET-IN-TREE", "high", rel, "AWS-style access key literal in tree"))
        hok = _OPENAI_KEY.search(head)
        if hok:
            findings.append(Finding("SECRET-IN-TREE", "high", rel, "OpenAI-style sk-/pk- token literal in tree"))