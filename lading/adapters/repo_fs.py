from __future__ import annotations

import os

from lading.adapters import LensReport, artifact_file
from lading.discover import walk
from lading.rules.repo import repo_rules


class _RepoCtx:
    def __init__(self, root: str, files: list[str], is_git: bool, tracked: set[str]) -> None:
        self.root = root
        self.files = files
        self.is_git = is_git
        self.tracked = tracked


def _git_tracked(root: str) -> tuple[bool, set[str]]:
    """Static git inspection only: 'git ls-files' is read-only, never runs code.

    Falls back to (False, set()) when git is unavailable so scanning never
    depends on the environment having git installed.
    """
    import subprocess

    git_dir = os.path.join(root, ".git")
    if not os.path.isdir(git_dir):
        return False, set()
    try:
        proc = subprocess.run(
            ["git", "-C", root, "ls-files", "-z"],
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return True, set()
    if proc.returncode != 0:
        return True, set()
    tracked = set(r.rstrip("\x00") for r in proc.stdout.split(b"\x00") if r)
    return True, tracked


def scan(root: str, cap_files: int = 5000) -> LensReport:
    report = LensReport()
    root = os.path.abspath(root)
    wr = walk(root)
    report.notes.extend(f"symlink outside root skipped: {p}" for p in wr.skipped_symlinks)
    report.notes.extend(f"walk error: {e}" for e in wr.errors)
    report.inputs.append(artifact_file(root, "repo-root", note="scan root", root=root))

    is_git, tracked = _git_tracked(root)
    report.inputs.append(_git_artifact(root, is_git))

    all_files = wr.files[:cap_files]
    ctx = _RepoCtx(root, all_files, is_git, tracked)
    for f in repo_rules(ctx):
        report.findings.append(f)

    # Inputs: key config + manifests + a bounded sample of the tree.
    for f in _key_files(all_files):
        report.inputs.append(artifact_file(f, "repo", root=root))
    for f in all_files[:250]:
        if f in _key_files(all_files):
            continue
        report.inputs.append(artifact_file(f, "repo", root=root))
    return report


def _git_artifact(root: str, is_git: bool):
    from lading.hashio import sha256_bytes

    from lading.model import Artifact

    if is_git:
        return Artifact(path=".git (present, ls-files read)", sha256=sha256_bytes(b"git"), kind="repo-root", size=0)
    return Artifact(path=".git (absent)", sha256=sha256_bytes(b"no-git"), kind="repo-root", size=0)


def _key_files(files: list[str]) -> list[str]:
    keys: list[str] = []
    for f in files:
        base = os.path.basename(f).lower()
        if base.startswith("readme") or base in (
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "poetry.lock",
            "Pipfile.lock",
            "requirements.txt",
            "pyproject.toml",
            "uv.lock",
            "Cargo.lock",
            "go.mod",
            "go.sum",
            ".env",
            ".gitignore",
            "Makefile",
        ):
            keys.append(f)
    return sorted(keys)