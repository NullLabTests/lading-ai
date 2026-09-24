from __future__ import annotations

import html
from typing import Any

_CSS = """
:root{color-scheme:dark}
*{box-sizing:border-box}
body{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;margin:0;background:#0d1117;color:#c9d1d9;line-height:1.45}
.wrap{max-width:960px;margin:0 auto;padding:32px 20px 80px}
header{border-bottom:1px solid #21262d;padding-bottom:16px;margin-bottom:24px}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:15px;margin:32px 0 10px;text-transform:uppercase;letter-spacing:.08em;color:#8b949e}
.meta{color:#8b949e;font-size:13px}
.pill{display:inline-block;border:1px solid #30363d;border-radius:999px;padding:1px 10px;margin:0 4px 4px 0;font-size:12px}
.counts{display:flex;gap:12px;flex-wrap:wrap}
.card{border:1px solid #30363d;border-radius:8px;padding:14px 16px;flex:1;min-width:120px}
.card b{font-size:26px;display:block}
.card.high b{color:#f85149}.card.med b{color:#d29922}.card.ok b{color:#3fb950}.card.exit b{color:#58a6ff}
tbody tr:nth-child(even) td{background:#161b22}
td,th{padding:6px 10px;vertical-align:top;border-bottom:1px solid #21262d;font-size:13px}
th{text-align:left;color:#8b949e;font-weight:600}
.badge{font-size:11px;border-radius:4px;padding:1px 7px;white-space:nowrap}
.badge.high{background:#f8514922;color:#f85149;border:1px solid #f8514955}
.badge.med{background:#d2992222;color:#d29922;border:1px solid #d2992255}
.badge.ok{background:#3fb95022;color:#3fb950;border:1px solid #3fb95055}
.id{font-weight:700;color:#58a6ff;white-space:nowrap}
.detail{color:#8b949e}
.art{word-break:break-all}
table{width:100%;border-collapse:collapse}
input.digest{color:#8b949e;font-size:11px}
footer{margin-top:48px;color:#6e7681;font-size:12px;border-top:1px solid #21262d;padding-top:16px}
"""


def _esc(s: Any) -> str:
    return html.escape(str(s), quote=True)


def render(receipt: dict[str, Any]) -> str:
    findings = receipt.get("findings", [])
    inputs = receipt.get("inputs", [])
    counts = receipt.get("counts", {})
    exit_code = receipt.get("exit", 0)
    rows = "".join(_finding_row(f) for f in sorted(findings, key=lambda x: (x["sev"], x["id"], x["artifact"])))
    inp_rows = "".join(_input_row(a) for a in inputs)
    note_items = "".join(f"<li>{_esc(n)}</li>" for n in receipt.get("notes", []))
    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>lading report · {_esc(receipt.get('command', 'scan'))}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
<header>
<h1>lading &mdash; {_esc(receipt.get("lading", "?"))}</h1>
<div class="meta">
mode <b>{_esc(receipt.get("mode", "offline"))}</b> · command <b>{_esc(receipt.get("command", "-"))}</b> · generated {_esc(receipt.get("generated_at", "-"))} ·
host_id <span class="pill">{_esc(receipt.get("host_id", ""))[:16]}&hellip;</span>
</div>
</header>

<section class="counts">
<div class="card high"><b>{counts.get("high", 0)}</b>high</div>
<div class="card med"><b>{counts.get("med", 0)}</b>med</div>
<div class="card ok"><b>{counts.get("ok", 0)}</b>ok</div>
<div class="card exit"><b>{exit_code}</b>exit code</div>
</section>

<h2>Findings &middot; {len(findings)}</h2>
<table>
<thead><tr><th>sev</th><th>id</th><th>artifact</th><th>detail</th></tr></thead>
<tbody>{rows}</tbody>
</table>

<h2>Inputs &middot; {len(inputs)} cargo items</h2>
<table>
<thead><tr><th>kind</th><th>path</th><th>sha256</th><th>size</th></tr></thead>
<tbody>{inp_rows}</tbody>
</table>

<h2>Notes</h2>
<ul>{note_items or "<li>none</li>"}</ul>

<footer>
lading is static analysis, not a sandbox. It never executes skill scripts,
project code, MCP servers or repo tests, and it makes no network requests.
This report is one file: inline CSS, no JavaScript, no external resources.
</footer>
</div>
</body>
</html>"""
    return doc


def _finding_row(f: dict) -> str:
    return (
        f"<tr><td><span class='badge {_esc(f['sev'])}'>{_esc(f['sev'])}</span></td>"
        f"<td class='id'>{_esc(f['id'])}</td>"
        f"<td class='art'>{_esc(f['artifact'])}</td>"
        f"<td class='detail'>{_esc(f['detail'])}</td></tr>"
    )


def _input_row(a: dict) -> str:
    h = a.get("sha256", "")
    sign = f"<span class='digest'>{_esc(h[:16])}&hellip;</span>" if h else "<span class='digest'>(unhashed)</span>"
    return (
        f"<tr><td>{_esc(a.get('kind', ''))}</td><td class='art'>{_esc(a.get('path', ''))}</td>"
        f"<td>{sign}</td><td>{a.get('size', 0)}</td></tr>"
    )