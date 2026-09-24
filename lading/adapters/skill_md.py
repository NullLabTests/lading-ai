from __future__ import annotations

import os

import yaml

from lading.adapters import LensReport, artifact_file
from lading.discover import walk
from lading.model import Finding
from lading.rules.net import net_rules
from lading.rules.secrets import secret_fs_rules, secret_text_rules
from lading.rules.undeclared import undeclared_rules

_SKILL_MD = "SKILL.md"
_SCRIPT_DIRS = ("scripts", "bin", "tools", "src")


class _SkillFileCtx:
    def __init__(self, relpath: str, text: str, kind: str) -> None:
        self.relpath = relpath
        self.text = text
        self.kind = kind


def find_skill_dirs(root: str) -> list[str]:
    """All directories under root that hold a SKILL.md (symlink-jailed)."""
    found: list[str] = []
    for f in walk(root).files:
        if os.path.basename(f) == _SKILL_MD:
            found.append(os.path.dirname(f))
    return sorted(set(found))


def _parse_frontmatter(md_text: str) -> tuple[dict, str]:
    fm: dict = {}
    body = md_text
    if md_text.startswith("---"):
        try:
            end = md_text.index("\n---", 3)
        except ValueError:
            return fm, body
        yaml_blob = md_text[3:end]
        body = md_text[end + len("\n---"):].lstrip("\n")
        try:
            fm = yaml.safe_load(yaml_blob) or {}
        except yaml.YAMLError:
            fm = {}
        if not isinstance(fm, dict):
            fm = {}
    return fm, body


def _declared_scripts(fm: dict, body: str) -> set[str]:
    declared: set[str] = set()
    for key in ("scripts", "script", "commands", "command"):
        v = fm.get(key)
        if isinstance(v, str):
            declared.add(v)
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    declared.add(item)
    for m in __import__("re").finditer(r"`([^`]+)`", body):
        cand = m.group(1).strip()
        if ("/" in cand or cand.endswith((".py", ".sh", ".rb", ".pl", ".js", ".mjs", ".cjs")) or cand.startswith(("./", "../"))):
            declared.add(cand)
    return declared


def scan_skill_dir(skill_dir: str, root: str, report: LensReport) -> None:
    rel = os.path.relpath(skill_dir, root).replace(os.sep, "/")
    files = walk(skill_dir).files
    md_path = os.path.join(skill_dir, _SKILL_MD)
    if md_path not in files:
        return

    try:
        md_text = open(md_path, "r", errors="replace").read()
    except OSError:
        md_text = ""
    fm, body = _parse_frontmatter(md_text)
    declared = _declared_scripts(fm, body)

    report.inputs.append(artifact_file(md_path, "skill", note="SKILL.md frontmatter", root=root))

    # SKILL.md body itself is a doc: URLs there are med, scripts here are moved on.
    body_ctx = _SkillFileCtx(f"{rel}/{_SKILL_MD}", md_text, "doc")
    report.findings.extend(net_rules(body_ctx))
    report.findings.extend(secret_text_rules(body_ctx))

    executables: list[str] = []
    for path in files:
        if path == md_path:
            continue
        from lading.discover import is_executable

        relpath = os.path.relpath(path, skill_dir).replace(os.sep, "/")
        relpath = f"{rel}/{relpath}"
        kind = "script" if _in_script_dir(relpath) else ("config" if path.endswith((".json", ".toml", ".yaml", ".yml")) else "source")
        try:
            text = open(path, "r", errors="replace").read()
            binaryish = _binaryish(text)
        except OSError:
            text, binaryish = "", True
        if is_executable(path):
            executables.append(os.path.relpath(path, skill_dir).replace(os.sep, "/"))
        if binaryish:
            report.inputs.append(artifact_file(path, "skill", note="binary attachment", root=root))
            report.findings.append(Finding("HAS-ATTACHMENT", "med", relpath, "binary file inside skill folder"))
            continue
        ctx = _SkillFileCtx(relpath, text, kind)
        report.inputs.append(artifact_file(path, "skill", root=root))
        for f in net_rules(ctx):
            report.findings.append(f)
        for f in secret_text_rules(ctx):
            report.findings.append(f)

    # UNDECLARED: executables not declared anywhere in SKILL.md.
    unit = _UndeclCtx(skill_root=rel, executables=executables, declared=declared)
    for f in undeclared_rules(unit):
        report.findings.append(f)

    # folder-level secret files sitting right next to the SKILL.md
    for f in secret_fs_rules(skill_dir):
        report.findings.append(
            Finding(f.id, f.sev, f"{rel}/{os.path.basename(f.artifact)}", f.detail)
        )


class _UndeclCtx:
    def __init__(self, skill_root: str, executables: list[str], declared: set[str]) -> None:
        self.skill_root = skill_root
        self.executables = executables
        self.declared = declared


def _in_script_dir(relpath: str) -> bool:
    parts = relpath.replace("\\", "/").split("/")
    return any(p in _SCRIPT_DIRS for p in parts[:-1])


def _binaryish(text: str) -> bool:
    """True when the head of the file contains genuine binary control bytes."""
    for ch in text[:1024]:
        o = ord(ch)
        if o == 0 or (o < 32 and ch not in "\t\n\r"):
            return True
        if o == 127:
            return True
    return False


def scan(root: str) -> LensReport:
    report = LensReport()
    report.notes.append(f"scanning skills under {root}")
    for skill_dir in find_skill_dirs(root):
        scan_skill_dir(skill_dir, root, report)
    return report