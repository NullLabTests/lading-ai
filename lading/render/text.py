from __future__ import annotations

from typing import Any

_COLORS = {"high": "\x1b[31;1m", "med": "\x1b[33;1m", "ok": "\x1b[32m"}
_RESET = "\x1b[0m"
_USE_COLOR = True


def _sevc(s: str) -> str:
    if not _USE_COLOR:
        return f"{s.upper():>4}"
    return f"{_COLORS.get(s, '')}{s.upper():>4}{_RESET}"


def render(receipt: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"lading {receipt.get('lading', '?')} · mode {receipt.get('mode', '?')} · host {receipt.get('host_id', '?')[:12]}…")
    if receipt.get("command"):
        lines.append(f"command: {receipt['command']}")
    findings: list[dict] = receipt.get("findings", [])
    if findings:
        lines.append(f"\nfindings ({len(findings)}):")
        for f in findings:
            lines.append(f"  {_sevc(f['sev'])}  {f['id']:<16} {f['artifact']}")
            lines.append(f"        {f['detail']}")
    else:
        lines.append("\nfindings: none")
    inputs = receipt.get("inputs", [])
    lines.append(f"\ninputs ({len(inputs)}): {sum(a.get('size', 0) for a in inputs)} bytes total")
    for a in inputs[:8]:
        lines.append(f"  {a['kind']:<16} {a['path']}  sha256 {a['sha256'][:12]}…" if a.get("sha256") else f"  {a['kind']:<16} {a['path']}")
    if len(inputs) > 8:
        lines.append(f"  … {len(inputs) - 8} more")
    counts = receipt.get("counts", {})
    lines.append(f"\ncounts: high {counts.get('high', 0)}, med {counts.get('med', 0)}, ok {counts.get('ok', 0)}")
    notes = receipt.get("notes", [])
    for n in notes:
        lines.append(f"note: {n}")
    lines.append(f"\nexit {receipt.get('exit', '?')}")
    return "\n".join(lines)


def set_color(enabled: bool) -> None:
    global _USE_COLOR
    _USE_COLOR = enabled