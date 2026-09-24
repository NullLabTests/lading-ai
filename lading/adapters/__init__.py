from __future__ import annotations

from dataclasses import dataclass, field

from lading.model import Artifact, Finding


@dataclass
class LensReport:
    """Standard accumulator returned by every adapter/lens."""

    inputs: list[Artifact] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def extend(self, other: "LensReport") -> None:
        self.inputs.extend(other.inputs)
        self.findings.extend(other.findings)
        self.notes.extend(other.notes)


def artifact_file(path: str, kind: str, note: str = "", root: str = "") -> Artifact:
    import os

    from lading.hashio import sha256_file

    try:
        h = sha256_file(path)
        size = os.path.getsize(path)
    except OSError:
        h = ""
        size = 0
    if root:
        display = os.path.relpath(path, root)
    else:
        display = path
    return Artifact(path=display, sha256=h, kind=kind, size=size, note=note)