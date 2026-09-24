from __future__ import annotations

import json
import os
import posixpath
import re
import zipfile
from dataclasses import dataclass, field

from lading.adapters import LensReport
from lading.hashio import sha256_stream
from lading.model import Artifact
from lading.rules.takeout import (
    dropped_finding,
    format_finding,
    kept_summary,
    redacted_finding,
)

MAX_ENTRY_BYTES = 64 * 1024 * 1024  # don't slurp huge files into memory for scanning


class ZipSlipError(ValueError):
    pass


def guard_path(name: str) -> str:
    """Reject zip entry names that would escape on extraction (zip-slip).

    Returns a normalized, safe relative name on success; raises ZipSlipError
    otherwise. Windows drive letters and absolute paths are also rejected.
    """
    if not name or "\x00" in name:
        raise ZipSlipError(f"unsafe entry name {name!r}")
    norm = name.replace("\\", "/")
    if norm.startswith("/"):
        raise ZipSlipError(f"absolute entry {name!r}")
    if re.match(r"^[A-Za-z]:", norm):
        raise ZipSlipError(f"drive-letter entry {name!r}")
    parts = posixpath.normpath(norm)
    if parts == ".." or parts.startswith("../") or "/../" in "/" + parts:
        raise ZipSlipError(f"entry escapes root: {name!r}")
    return norm


@dataclass
class Thread:
    """One conversation (a takeout thread) with its original object."""

    file: str            # entry name inside the zip
    index: int           # index within its file (0 for one-per-file formats)
    title: str
    obj: object          # parsed JSON holding this thread (redacted in place)
    texts: str           # all text joined, used for --drop filtering
    has_attachment: bool = False
    has_system_prompt: bool = False
    redactions: int = 0
    dropped: bool = False


@dataclass
class ParsedFile:
    """A zip entry that was parsed into one or more threads."""

    name: str
    array: bool  # True -> entry holds a list of thread objects
    threads: list[Thread] = field(default_factory=list)


_REDACT_MARK = "[REDACTED]"

# Order matters: long token-aware patterns first.
_REDACT_RE = [
    re.compile(r"AKIA[0-9A-Z]{16}|(?:ASIA|AIDA)[0-9A-Z]{16}"),
    re.compile(r"(?i)\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"(?i)(api[_-]?key|access[_-]?token|auth[_-]?token|bearer|secret|password|passwd|pwd)([A-Za-z0-9_\-./+]{24,})"),
    re.compile(r"\b(?:[A-Fa-f0-9]{40,}|[A-Za-z0-9+/]{40,}={0,2})\b"),
    re.compile(r"(?i)\b(?:key|token|secret|password|passwd|pwd)\s(?:is|was|=|:)\s+[A-Za-z0-9_\-./+]{12,}"),
]

_LOOKS_SECRET = re.compile(r"""(?i)api[_-]?key|token|secret|password|credentials|authorization|bearer""", re.IGNORECASE)


def redact_text(text: str) -> tuple[str, int]:
    count = 0
    for rx in _REDACT_RE:
        new, n = rx.subn(_REDACT_MARK, text)
        count += n
        text = new
    return text, count


def _walk_strings(obj, replace):
    changed = 0
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            obj[k] = _walk_strings(obj[k], replace)
        return obj
    if isinstance(obj, list):
        for i, item in enumerate(obj):
            obj[i] = _walk_strings(item, replace)
        return obj
    if isinstance(obj, str):
        new = replace(obj)
        if new is not obj:
            changed += 1
        return new
    return obj


def deep_redact(obj) -> tuple[object, int]:
    """Redact all string leaves of a JSON object in place; returns count."""
    counter = {"n": 0}

    def cb(s: str) -> str:
        red, n = redact_text(s)
        counter["n"] += n
        return red

    _walk_strings(obj, cb)
    return obj, counter["n"]


def deep_text(obj) -> str:
    """Join all string leaves — used for --drop filtering and prompts/attachments."""
    bits: list[str] = []

    def visit(o) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                if k.lower() in ("title", "name", "text", "content"):
                    if isinstance(v, str):
                        bits.append(v)
                visit(v)
        elif isinstance(o, list):
            for item in o:
                visit(item)
        elif isinstance(o, str):
            bits.append(o)

    visit(obj)
    return "\n".join(bits)


def entry_text(data: bytes) -> str:
    """Decode entry bytes as text when plausible; else ''."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    return text


class TakeoutReader:
    """Read a takeout zip in memory with a zip-slip guard on entry names."""

    def __init__(self, zip_path: str) -> None:
        self.zip_path = zip_path
        self.zf = zipfile.ZipFile(zip_path)

    def __enter__(self) -> "TakeoutReader":
        return self

    def __exit__(self, *exc) -> None:
        self.zf.close()

    def names(self) -> list[str]:
        return [n for n in self.zf.namelist() if not n.endswith("/")]

    def read(self, name: str) -> bytes:
        guard_path(name)
        info = self.zf.getinfo(name)
        if info.file_size > MAX_ENTRY_BYTES:
            raise ValueError(f"entry too large to scan: {name} ({info.file_size} bytes)")
        with self.zf.open(name) as fh:
            return fh.read()

    def iter_entries(self):
        for name in self.names():
            safe = guard_path(name)
            yield safe, self.read(name)


def json_entry(data: bytes) -> object | None:
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return obj


def write_cleaned_zip(out_path: str, entries: list[tuple[str, bytes]]) -> None:
    """Write a fresh zip from (name, data) pairs, guarding names again."""
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            safe = guard_path(name)
            zf.writestr(safe, data)


def make_source_artifact(zip_path: str) -> Artifact:
    try:
        h = sha256_file_(zip_path)
        size = os.path.getsize(zip_path)
    except OSError:
        h, size = "", 0
    return Artifact(path=os.path.basename(zip_path), sha256=h, kind="takeout", size=size)


def sha256_file_(path: str) -> str:
    with open(path, "rb") as f:
        return sha256_stream(f)


@dataclass
class TakeoutRun:
    """Accumulates a takeout scan + cleanup before writing the report."""

    report: LensReport = field(default_factory=LensReport)
    parsed: dict[str, ParsedFile] = field(default_factory=dict)
    formats: list[str] = field(default_factory=list)

    def add_format(self, fmt: str) -> None:
        if fmt not in self.formats:
            self.formats.append(fmt)

    def file_for(self, name: str, array: bool) -> ParsedFile:
        pf = self.parsed.get(name)
        if pf is None:
            pf = ParsedFile(name=name, array=array)
            self.parsed[name] = pf
        return pf

    def threads(self) -> list[Thread]:
        out: list[Thread] = []
        for pf in self.parsed.values():
            out.extend(pf.threads)
        return out

    def summarize(self, source_zip: str, out_path: str = "", drop_pattern: str = "") -> None:
        kept = len([t for t in self.threads() if not t.dropped])
        for fmt in self.formats:
            self.report.findings.append(format_finding(source_zip, fmt))
        self.report.findings.append(kept_summary(source_zip, kept))
        if out_path:
            self.report.inputs.append(
                Artifact(path=os.path.basename(out_path), sha256=sha256_file_(out_path), kind="takeout-clean", size=os.path.getsize(out_path))
            )
        self.report.notes.append(f"takeout formats detected: {', '.join(self.formats) or 'none'}")
        if drop_pattern:
            self.report.notes.append(f"drop filter: /{drop_pattern}/")


def run_takeout(zip_path: str, out_path: str = "", drop: str = "") -> LensReport:
    """Scan a takeout zip, drop+redact, write a cleaned zip, return the report.

    Only command that writes an archive. Never uploads. Never extracts to
    disk — everything is read and rewritten in memory with zip-slip guards.
    """
    from lading.adapters import takeout_claude, takeout_gemini, takeout_openai

    run = TakeoutRun()
    source_key = os.path.basename(zip_path)
    run.report.inputs.append(make_source_artifact(zip_path))

    with TakeoutReader(zip_path) as reader:
        entries: dict[str, bytes] = {}
        ordered: list[str] = []
        for name in reader.names():
            try:
                data = reader.read(name)
            except ValueError as exc:
                run.report.notes.append(f"entry skipped: {name} ({exc})")
                continue
            entries[name] = data
            ordered.append(name)
            claim = _claim_format(name, data)
            if claim == "openai":
                takeout_openai.collect(name, data, run)
            elif claim == "claude":
                takeout_claude.collect(name, data, run)
            elif claim == "gemini":
                takeout_gemini.collect(name, data, run)

        drop_rx = re.compile(drop) if drop else None

        # Findings that describe the raw cargo.
        for name in ordered:
            run.report.inputs.append(_entry_artifact(name, entries[name]))

        # Drop + redact.
        for pf in run.parsed.values():
            for t in pf.threads:
                if drop_rx and drop_rx.search(t.title + "\n" + t.texts):
                    t.dropped = True
                    run.report.findings.append(dropped_finding(f"{pf.name} [{t.title}]", drop))
                    continue
                red, count = deep_redact(t.obj)
                t.redactions = count
                if count:
                    run.report.findings.append(redacted_finding(f"{pf.name} [{t.title}]", count))

        # Build the cleaned archive.
        out_entries: list[tuple[str, bytes]] = []
        for name in ordered:
            if name in run.parsed:
                pf = run.parsed[name]
                kept = [t for t in pf.threads if not t.dropped]
                if not kept:
                    run.report.notes.append(f"all threads dropped from {name}; entry omitted from cleaned archive")
                    continue
                if pf.array:
                    new_data = json.dumps([t.obj for t in kept], ensure_ascii=False, indent=2)
                else:
                    new_data = json.dumps(kept[0].obj, ensure_ascii=False, indent=2)
                out_entries.append((name, new_data.encode("utf-8")))
            else:
                out_entries.append((name, entries[name]))

        if out_path:
            write_cleaned_zip(out_path, out_entries)

    run.summarize(source_key, out_path, drop)
    return run.report


def _claim_format(name: str, data: bytes) -> str | None:
    """Return the takeout format that owns this entry, or None.

    Structured detection so a ChatGPT conversations.json is never also parsed
    as Claude (which would double-report every redaction/drop)."""
    dl = name.lower().replace("\\", "/")
    base = dl.split("/")[-1]
    obj = json_entry(data)
    if "gemini" in dl:
        return "gemini"
    if obj is not None:
        if isinstance(obj, dict):
            if "chat_messages" in obj or obj.get("type") == "conversation":
                return "claude"
        elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
            first = obj[0]
            if "chat_messages" in first or ("uuid" in first and "name" in first):
                return "claude"
            if "messages" in first or "mapping" in first or "create_time" in first:
                return "openai"
    if base.endswith("conversations.json"):
        return "openai"
    if base.startswith("conversation"):
        return "claude"
    return None


def _entry_artifact(name: str, data: bytes) -> Artifact:
    import hashlib

    h = hashlib.sha256(data).hexdigest()
    return Artifact(path=name, sha256=h, kind="takeout-entry", size=len(data))