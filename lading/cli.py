from __future__ import annotations

import argparse
import json
import os
import re
import sys
import zipfile

from lading import __version__
from lading.adapters import LensReport
from lading.model import Artifact, Finding, Receipt
from lading.render import html as html_render
from lading.render import text as text_render

RULES_CACHE: dict | None = None


class UsageError(Exception):
    pass


def _rules_defs() -> list[dict]:
    global RULES_CACHE
    if RULES_CACHE is None:
        from lading.rules import RULES_DEF

        RULES_CACHE = RULES_DEF
    return RULES_CACHE


def _common_flags() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--json", action="store_true", help="machine-readable output (the Receipt JSON)")
    p.add_argument("--fail-on", default="high", choices=["high", "med", "any"], help="exit 1 when findings at/above this level exist (default high)")
    p.add_argument("--offline", action="store_true", default=True, help="offline mode (default, and the only mode)")
    p.add_argument("--online", action="store_true", help="refused: lading never goes on the network")
    return p


def build_argparser() -> argparse.ArgumentParser:
    common = _common_flags()
    p = argparse.ArgumentParser(
        prog="lading",
        description="A bill of lading for work done by machines. Static, offline, no model.",
        parents=[common],
    )
    p.add_argument("--version", action="version", version=f"lading {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("scan", parents=[common], help="scan cwd + known home agent dirs (skills/MCP/agent configs)")
    sp.add_argument("paths", nargs="*")

    ap = sub.add_parser("agents", parents=[common], help="scan explicit dirs for skills, MCP servers, agent configs")
    ap.add_argument("paths", nargs="*")

    tp = sub.add_parser("takeout", parents=[common], help="sanitize a chat export: drop threads, redact secrets, write a clean zip")
    tp.add_argument("zip", nargs="?", help="path to takeout .zip")
    tp.add_argument("--drop", default="", help="regex; matching threads/messages are dropped")
    tp.add_argument("--out", default="", help="cleaned zip path (default: <input>.clean.zip)")

    rp = sub.add_parser("repo", parents=[common], help="static audit of a git tree")
    rp.add_argument("path", nargs="?", default=".")

    rep = sub.add_parser("report", parents=[common], help="render a receipt.json into a single-file HTML report")
    rep.add_argument("receipt", help="path to a lading receipt.json")
    rep.add_argument("--out", default="", help="HTML output path (default: .lading/report.html)")

    dp = sub.add_parser("diff", parents=[common], help="compare two receipts: findings added/removed by id+artifact")
    dp.add_argument("old", help="old receipt.json")
    dp.add_argument("new", help="new receipt.json")

    sub.add_parser("rules", parents=[common], help="print the rule catalog")
    return p


def _online_refused(args) -> None:
    if getattr(args, "online", False):
        raise UsageError("--online is refused: lading is offline-only by design")


def _write_side_outputs(receipt: Receipt, json_mode: bool = False) -> None:
    os.makedirs(".lading", exist_ok=True)
    receipt_j = os.path.join(".lading", "receipt.json")
    html_j = os.path.join(".lading", "report.html")
    with open(receipt_j, "w") as f:
        f.write(receipt.to_json() + "\n")
    with open(html_j, "w") as f:
        f.write(html_render.render(receipt.to_dict()))
    line = f"written: {receipt_j} + {html_j}"
    if json_mode:
        sys.stderr.write(line + "\n")
    else:
        print(line)


def _emit(receipt: Receipt, json_mode: bool) -> None:
    if json_mode:
        print(receipt.to_json())
    else:
        print(text_render.render(receipt.to_dict()))


# ---------------------------------------------------------------- commands


def cmd_scan(args, roots: list[str]) -> Receipt:
    from lading.adapters import agent_configs, mcp_json, skill_md

    report = LensReport()
    for root in roots:
        for lens in (skill_md.scan, mcp_json.scan, agent_configs.scan):
            report.extend(lens(root))
    return _finalize("scan " + " ".join(roots), report, args.fail_on)


def cmd_agents(args) -> Receipt:
    if not args.paths:
        raise UsageError("lading agents needs at least one path")
    roots: list[str] = []
    for pth in args.paths:
        ap = os.path.abspath(pth)
        if not os.path.isdir(ap):
            raise UsageError(f"not a directory: {pth}")
        roots.append(ap)
    return cmd_scan(args, roots)


def cmd_takeout(args) -> Receipt:
    if not args.zip:
        raise UsageError("lading takeout needs a path to a takeout zip")
    src = args.zip
    if not os.path.isfile(src):
        raise UsageError(f"no such file: {src}")
    out = args.out or _default_clean_name(src)
    if not out.endswith(".zip"):
        out += ".zip"

    from lading.adapters import takeout_common as tc

    if args.drop:
        try:
            re.compile(args.drop)
        except re.error as exc:
            raise UsageError(f"invalid --drop regex: {exc}")

    try:
        report = tc.run_takeout(src, out_path=out, drop=args.drop)
    except (OSError, zipfile.BadZipFile) as exc:
        raise UsageError(f"cannot open zip {src}: {exc}")

    receipt = Receipt(command=f"takeout {src} --out {out}" + (f" --drop {args.drop!r}" if args.drop else ""))
    receipt.inputs = report.inputs
    receipt.findings = report.findings
    receipt.notes = report.notes
    receipt.exit = int(_exceeds_threshold(
        [(f.sev, f.id, f.artifact, f.detail) for f in receipt.findings], args.fail_on
    ))
    receipt.notes.append("cleaned archive written; it never uploads")
    return receipt


def cmd_repo(args) -> Receipt:
    from lading.adapters import repo_fs

    path = args.path or "."
    ap = os.path.abspath(path)
    if not os.path.isdir(ap):
        raise UsageError(f"not a directory: {path}")
    report = repo_fs.scan(ap)
    return _finalize(f"repo {path}", report, args.fail_on)


def cmd_report(args) -> Receipt:
    if not os.path.isfile(args.receipt):
        raise UsageError(f"no such receipt: {args.receipt}")
    try:
        with open(args.receipt) as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:
        raise UsageError(f"cannot read receipt {args.receipt}: {exc}")
    out = args.out or os.path.join(".lading", "report.html")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w") as f:
        f.write(html_render.render(data))
    receipt = Receipt(command=f"report {args.receipt} --out {out}")
    from lading.hashio import sha256_file

    receipt.inputs.append(
        Artifact(path=os.path.basename(args.receipt), sha256=sha256_file(args.receipt), kind="receipt", size=os.path.getsize(args.receipt))
    )
    n = len(data.get("findings", []))
    ef = int(data.get("exit", 0))
    receipt.findings.append(Finding("REPORT-WRITTEN", "ok", out, f"HTML report rendered from receipt with {n} finding(s), exit {ef}"))
    receipt.exit = 0
    receipt.notes.append("single-file HTML: inline CSS, no JS, no external resources")
    return receipt


def cmd_diff(args) -> Receipt:
    old = _load_receipt_table(args.old)
    new = _load_receipt_table(args.new)
    added = [f for f in new if f not in old]
    removed = [f for f in old if f not in new]
    added.sort()
    removed.sort()

    receipt = Receipt(command=f"diff {args.old} {args.new}")
    for f in added:
        receipt.findings.append(_map_f(f, "ADDED"))
    for f in removed:
        receipt.findings.append(_map_f(f, "REMOVED"))
    ef = 1 if _exceeds_threshold(added, args.fail_on) else 0
    receipt.exit = ef
    receipt.notes.append(f"{len(added)} finding(s) added, {len(removed)} removed")
    return receipt


def _exceeds_threshold(rows: list[tuple], fail_on: str) -> bool:
    if fail_on == "high":
        return any(r[0] == "high" for r in rows)
    if fail_on in ("med", "any"):
        return any(r[0] in ("high", "med") for r in rows)
    return False


def _map_f(f: tuple, tag: str) -> Finding:
    sev, rid, artifact, detail = f
    return Finding(id=rid, sev=sev, artifact=artifact, detail=f"{tag} by id+artifact: {detail}")


def _load_receipt_table(path: str) -> list[tuple]:
    if not os.path.isfile(path):
        raise UsageError(f"no such receipt: {path}")
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:
        raise UsageError(f"cannot read receipt {path}: {exc}")
    table: set[tuple] = set()
    for ff in data.get("findings", []):
        table.add((ff.get("sev", "ok"), ff.get("id", "?"), ff.get("artifact", ""), ff.get("detail", "")))
    return sorted(table)


def cmd_rules(args) -> Receipt:
    defs = _rules_defs()
    receipt = Receipt(command="rules")
    lines = [f"lading {__version__} rule catalog ({len(defs)} rules)"]
    lines.append(f"{'id':<16} {'sev':<5} lens      catches")
    lines.append("-" * 78)
    for r in sorted(defs, key=lambda d: (d["lens"], d["sev"], d["id"])):
        lines.append(f"{r['id']:<16} {r['sev']:<5} {r['lens']:<9} {r['catches']}")
    catalog = "\n".join(lines)
    if args.json:
        sys.stderr.write(catalog + "\n")
    else:
        print(catalog)
    receipt.findings.append(Finding("RULES-CATALOG", "ok", "rule catalog", f"{len(defs)} rules registered"))
    receipt.exit = 0
    return receipt


def _finalize(command: str, report: LensReport, fail_on: str) -> Receipt:
    receipt = Receipt(command=command)
    receipt.inputs = report.inputs
    receipt.findings = report.findings
    receipt.notes = report.notes
    receipt.set_exit(fail_on)
    return receipt


def _default_clean_name(src: str) -> str:
    root, ext = os.path.splitext(src)
    return f"{root}.clean{ext or '.zip'}"


def main(argv: list[str] | None = None) -> int:
    parser = build_argparser()
    args = parser.parse_args(argv)
    try:
        _online_refused(args)
        if args.command == "scan":
            roots = args.paths or _default_scan_roots()
            receipt = cmd_scan(args, roots)
        elif args.command == "agents":
            receipt = cmd_agents(args)
        elif args.command == "takeout":
            receipt = cmd_takeout(args)
        elif args.command == "repo":
            receipt = cmd_repo(args)
        elif args.command == "report":
            receipt = cmd_report(args)
        elif args.command == "diff":
            receipt = cmd_diff(args)
        elif args.command == "rules":
            receipt = cmd_rules(args)
        else:  # pragma: no cover - argparse prevents this
            raise UsageError(f"unknown command: {args.command}")
    except UsageError as exc:
        sys.stderr.write(f"lading: error: {exc}\n")
        return 2
    except KeyboardInterrupt:
        sys.stderr.write("lading: interrupted\n")
        return 130

    receipt.mode = "offline"
    if args.command in ("scan", "agents", "takeout", "repo"):
        _write_side_outputs(receipt, args.json)
        _emit(receipt, args.json)
    else:
        _emit(receipt, args.json)
    return receipt.exit


def _default_scan_roots() -> list[str]:
    roots = [os.getcwd()]
    home = os.path.expanduser("~")
    for rel in (".claude", ".config/opencode", ".cursor", ".gemini", ".config/lading"):
        p = os.path.join(home, rel)
        if os.path.isdir(p) and p not in roots:
            roots.append(p)
    return roots