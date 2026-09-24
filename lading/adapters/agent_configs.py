from __future__ import annotations

import json
import os

from lading.adapters import LensReport, artifact_file
from lading.discover import is_executable, walk
from lading.model import Finding
from lading.rules.net import net_rules
from lading.rules.secrets import secret_fs_rules, secret_text_rules

_CONFIG_NAMES = {
    "opencode.json",
    "opencode.jsonc",
    "agent.json",
    ".cursor/mcp.json",
    "agents.json",
    "config.json",
}
_MD_FRONT = {".md"}  # only top-level markdown with YAML frontmatter counts


class _Ctx:
    def __init__(self, relpath: str, text: str, kind: str) -> None:
        self.relpath = relpath
        self.text = text
        self.kind = kind


def find_agent_units(root: str) -> list[str]:
    """Config files and frontmatter .md agent definition files."""
    out: list[str] = []
    for f in walk(root).files:
        base = os.path.basename(f)
        if base in _CONFIG_NAMES:
            out.append(f)
            continue
        rel = os.path.relpath(f, root).replace(os.sep, "/")
        if base.endswith(".md") and "/" not in rel and _has_frontmatter(f):
            out.append(f)
    return sorted(out)


def _has_frontmatter(path: str) -> bool:
    try:
        head = open(path, "r", errors="replace").read(4096)
    except OSError:
        return False
    return head.startswith("---\n")


def scan_unit(path: str, root: str, report: LensReport) -> None:
    rel = os.path.relpath(path, root).replace(os.sep, "/")
    try:
        text = open(path, "r", errors="replace").read()
    except OSError:
        text = ""
    report.inputs.append(artifact_file(path, "agent", root=root))
    is_json = path.endswith((".json", ".jsonc"))
    kind = "config" if is_json else "doc"
    ctx = _Ctx(rel, text, kind)
    for f in net_rules(ctx):
        report.findings.append(f)
    for f in secret_text_rules(ctx):
        report.findings.append(f)

    if is_json:
        _referenced_scripts(text, rel, root, path, report)


def _referenced_scripts(text: str, rel: str, root: str, path: str, report: LensReport) -> None:
    """opencode-style configs list referenced script/tool files; verify they exist."""
    try:
        if path.endswith(".jsonc"):
            text = _strip_jsonc(text)
        data = json.loads(text)
    except ValueError:
        data = None
    if not isinstance(data, dict):
        return
    refs: list[str] = []
    for key in ("skill", "skills", "scripts", "tools", "subagents"):
        v = data.get(key)
        if isinstance(v, str):
            refs.append(v)
        elif isinstance(v, list):
            refs.extend(str(x) for x in v if isinstance(x, str))
    seen: set[str] = set()
    for ref in refs:
        if ref in seen:
            continue
        seen.add(ref)
        target = os.path.join(os.path.dirname(path), ref)
        exists = os.path.isfile(target) or os.path.isdir(target)
        if exists:
            report.inputs.append(artifact_file(target, "agent-ref", note="referenced by agent config", root=root))
            report.findings.append(Finding("AGENT-REF", "ok", f"{rel} -> {ref}", "referenced script present"))
            if os.path.isfile(target) and not target.endswith((".json", ".jsonc", ".md")):
                try:
                    ref_text = open(target, "r", errors="replace").read()
                except OSError:
                    ref_text = ""
                rctx = _Ctx(f"{rel} -> {ref}", ref_text, "script" if is_executable(target) or ref.endswith((".py", ".sh", ".js", ".rb")) else "source")
                report.findings.extend(net_rules(rctx))
                report.findings.extend(secret_text_rules(rctx))
        else:
            report.inputs.append(_missing_artifact(ref, root, rel))
            report.findings.append(Finding("AGENT-REF", "ok", f"{rel} -> {ref}", "referenced script MISSING"))


def _missing_artifact(ref: str, root: str, rel: str):
    from lading.model import Artifact

    return Artifact(path=f"{rel} -> {ref} (missing)", sha256="", kind="agent-ref", size=0)


def _strip_jsonc(text: str) -> str:
    out: list[str] = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("//"):
            continue
        out.append(line)
    return "\n".join(out)


def scan(root: str) -> LensReport:
    report = LensReport()
    for unit in find_agent_units(root):
        scan_unit(unit, root, report)
    for f in secret_fs_rules(root):
        report.findings.append(f)
    return report