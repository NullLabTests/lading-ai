from __future__ import annotations

import json
import os

from lading.adapters import LensReport, artifact_file
from lading.discover import walk
from lading.hashio import sha256_bytes
from lading.model import Artifact, Finding
from lading.rules.net import net_rules
from lading.rules.secrets import secret_text_rules

_MCP_NAMES = {".mcp.json", "mcp.json", ".mcp", "mcp-config.json"}


class _Ctx:
    def __init__(self, relpath: str, text: str, kind: str) -> None:
        self.relpath = relpath
        self.text = text
        self.kind = kind


def find_mcp_files(root: str) -> list[str]:
    out = []
    for f in walk(root).files:
        if os.path.basename(f) in _MCP_NAMES:
            out.append(f)
    return sorted(out)


def _value_artifact(name: str, value: str, kind: str) -> Artifact:
    """Artifact for a derived value (server command/url/env), hashed, not raw."""
    data = value.encode("utf-8", "replace")
    h = sha256_bytes(data)
    # Never echo secret-shaped values into the receipt path.
    display = f"[{kind} {name}]"
    return Artifact(path=display, sha256=h, kind=kind, size=len(data))


def scan_mcp_file(path: str, root: str, report: LensReport) -> None:
    rel = os.path.relpath(path, root).replace(os.sep, "/")
    report.inputs.append(artifact_file(path, "mcp", root=root))
    try:
        text = open(path, "r", errors="replace").read()
        data = json.loads(text)
    except (OSError, ValueError) as exc:
        report.findings.append(Finding("MCP-UNPARSEABLE", "med", rel, f"cannot parse mcp config: {exc}"))
        return
    if isinstance(data, dict):
        servers = data.get("mcpServers", data.get("servers", {}))
    else:
        servers = {}
    if not isinstance(servers, dict):
        return
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        label = f"{rel}#{name}"
        cmd = cfg.get("command")
        args = cfg.get("args") or []
        url = cfg.get("url")
        env = cfg.get("env") or {}
        parts: list[str] = []
        if isinstance(cmd, str):
            parts.append(cmd)
        elif isinstance(cmd, list):
            parts.extend(str(x) for x in cmd)
        if isinstance(args, list):
            parts.extend(str(x) for x in args)
        cmd_txt = " ".join(parts)
        if url:
            report.inputs.append(_value_artifact(name, str(url), "mcp-server-url"))
            report.findings.append(Finding("MCP-URL", "med", label, f"remote server endpoint: {url}"))
        if cmd_txt.strip():
            report.inputs.append(_value_artifact(name, cmd_txt, "mcp-server-command"))
            report.findings.append(Finding("MCP-CMD", "ok", label, f"server launches: {cmd_txt[:80]}"))
            ctx = _Ctx(label, cmd_txt, "config")
            for f in net_rules(ctx):
                report.findings.append(f)
        if isinstance(env, dict) and env:
            env_txt = "\n".join(f"{k}={v}" for k, v in env.items() if isinstance(v, str))
            report.inputs.append(_value_artifact(name, env_txt, "mcp-server-env"))
            for f in secret_text_rules(_Ctx(f"{label} (env)", env_txt, "config")):
                report.findings.append(f)


def scan(root: str) -> LensReport:
    report = LensReport()
    for path in find_mcp_files(root):
        scan_mcp_file(path, root, report)
    return report