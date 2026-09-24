from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from lading import __version__

SEVERITIES = ("ok", "med", "high")
SEV_ORDER = {"ok": 0, "med": 1, "high": 2}

# Fixed salt so host_id is deterministic across runs on the same host while
# never being the raw hostname (the salt is not secret; the point is hashing).
_HOST_SALT = b"lading-0.1.0-host-salt"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def host_id() -> str:
    raw = _hostname().encode("utf-8", "replace")
    return hashlib.sha256(_HOST_SALT + raw).hexdigest()


def _hostname() -> str:
    # No socket import: this package must never touch network modules.
    try:
        return os.uname().nodename
    except (AttributeError, OSError):
        return os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or "unknown"


@dataclass(frozen=True)
class Artifact:
    """One piece of cargo that was on board: a hashed input."""

    path: str
    sha256: str
    kind: str
    size: int
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "path": self.path,
            "sha256": self.sha256,
            "kind": self.kind,
            "size": self.size,
        }
        if self.note:
            d["note"] = self.note
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Artifact":
        return cls(
            path=str(d["path"]),
            sha256=str(d["sha256"]),
            kind=str(d["kind"]),
            size=int(d.get("size", 0)),
            note=str(d.get("note", "")),
        )


@dataclass(frozen=True)
class Finding:
    """A rule fired against one artifact or unit."""

    id: str
    sev: str
    artifact: str
    detail: str

    def __post_init__(self) -> None:
        if self.sev not in SEVERITIES:
            raise ValueError(f"invalid severity {self.sev!r}")

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "sev": self.sev,
            "artifact": self.artifact,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        return cls(
            id=str(d["id"]),
            sev=str(d["sev"]),
            artifact=str(d["artifact"]),
            detail=str(d["detail"]),
        )

    def sort_key(self):
        return (self.id, self.artifact, self.detail)


@dataclass
class Receipt:
    """The one shape every command writes. No per-command JSON."""

    lading: str = __version__
    generated_at: str = field(default_factory=utcnow)
    host_id: str = field(default_factory=host_id)
    mode: str = "offline"
    command: str = ""
    inputs: list[Artifact] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    exit: int = 0

    def counts(self) -> dict[str, int]:
        c = {"high": 0, "med": 0, "ok": 0}
        for f in self.findings:
            if f.sev in c:
                c[f.sev] += 1
        return c

    def sort(self) -> None:
        self.inputs.sort(key=lambda a: (a.path, a.kind))
        self.findings.sort(key=Finding.sort_key)
        self.notes.sort()

    def set_exit(self, fail_on: str) -> None:
        """fail_on: 'high'|'med'|'any'. 'ok' findings never fail."""
        counts = self.counts()
        if fail_on == "high":
            self.exit = 1 if counts["high"] > 0 else 0
        elif fail_on == "med":
            self.exit = 1 if counts["high"] + counts["med"] > 0 else 0
        elif fail_on == "any":
            self.exit = 1 if counts["high"] + counts["med"] > 0 else 0
        else:
            raise ValueError(f"unknown fail-on level {fail_on!r}")

    def to_dict(self) -> dict[str, Any]:
        self.sort()
        return {
            "lading": self.lading,
            "generated_at": self.generated_at,
            "host_id": self.host_id,
            "mode": self.mode,
            "command": self.command,
            "inputs": [a.to_dict() for a in self.inputs],
            "findings": [f.to_dict() for f in self.findings],
            "notes": list(self.notes),
            "counts": self.counts(),
            "exit": self.exit,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Receipt":
        r = cls(
            lading=str(d.get("lading", "")),
            generated_at=str(d.get("generated_at", "")),
            host_id=str(d.get("host_id", "")),
            mode=str(d.get("mode", "")),
            command=str(d.get("command", "")),
            inputs=[Artifact.from_dict(i) for i in d.get("inputs", [])],
            findings=[Finding.from_dict(f) for f in d.get("findings", [])],
            notes=[str(n) for n in d.get("notes", [])],
            exit=int(d.get("exit", 0)),
        )
        return r

    def to_json(self) -> str:
        import json

        return json.dumps(self.to_dict(), sort_keys=True, indent=2)