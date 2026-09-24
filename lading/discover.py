from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Iterator


@dataclass
class WalkResult:
    files: list[str] = field(default_factory=list)  # absolute paths
    skipped_symlinks: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _inside(root_real: str, target_real: str) -> bool:
    """True if target_real is root_real or below it. root_real must be real."""
    if target_real == root_real:
        return True
    return os.path.commonpath([root_real, target_real]) == root_real


def walk(root: str, max_depth: int = 256) -> WalkResult:
    """Walk `root`, never following a symlink that escapes the scan root.

    Directories: a symlinked dir whose real target lies inside the root is
    followed (the target is still in the jai); one that points outside is
    recorded and skipped. Files: a symlink whose real target is outside the
    root is skipped and recorded.
    """
    out = WalkResult()
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        out.errors.append(f"not a directory: {root}")
        return out
    root_real = os.path.realpath(root)

    def safe_join(base: str, name: str) -> str:
        joined = os.path.join(base, name)
        # guard against '..' tricks even when the name came from scandir.
        return os.path.abspath(joined)

    stack: list[tuple[str, int]] = [(root, 0)]
    while stack:
        base, depth = stack.pop()
        try:
            entries = os.scandir(base)
        except OSError as exc:
            out.errors.append(f"cannot read {base}: {exc}")
            continue
        with entries as it:
            for entry in it:
                full = safe_join(base, entry.name)
                try:
                    is_link = entry.is_symlink()
                except OSError:
                    out.errors.append(f"cannot stat {full}")
                    continue
                if is_link:
                    try:
                        target_real = os.path.realpath(full)
                    except OSError as exc:
                        out.errors.append(f"broken symlink {full}: {exc}")
                        continue
                    if not _inside(root_real, target_real):
                        out.skipped_symlinks.append(full)
                        continue
                    # inside root: follow it, but only as a file reference.
                    if os.path.isdir(target_real):
                        if depth + 1 > max_depth:
                            out.skipped_symlinks.append(full)
                            continue
                        stack.append((target_real, depth + 1))
                    else:
                        out.files.append(full)
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if depth + 1 > max_depth:
                        out.skipped_symlinks.append(full)
                        continue
                    # A directory reached only via an in-root symlink already
                    # became its real path; plain dirs stay where they are.
                    stack.append((full, depth + 1))
                elif entry.is_file(follow_symlinks=False):
                    out.files.append(full)
    # Deterministic order regardless of FS order.
    out.files.sort()
    out.skipped_symlinks.sort()
    out.errors.sort()
    return out


def iter_files(root: str) -> Iterator[str]:
    """Convenience: yield only files, silently skipping jail escapes."""
    for f in walk(root).files:
        yield f


def is_executable(path: str) -> bool:
    if not os.path.isfile(path):
        return False
    # Any file with a shebang or the exec bit set counts as executable.
    if os.access(path, os.X_OK) and not os.path.isdir(path):
        return True
    try:
        with open(path, "rb") as f:
            head = f.read(2)
    except OSError:
        return False
    return head == b"#!"