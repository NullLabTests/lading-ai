#!/usr/bin/env bash
# lading — the five-second tour.
#
# Runs every command against the bundled fixture suite, showing flags and
# exit codes, without touching anything outside a throwaway temp dir.
#
# Prereqs: python3, git. No network; nothing is uploaded.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIX="$ROOT/tests/fixtures"
LADING="$ROOT/.venv/bin/lading"

if [ ! -x "$LADING" ]; then
  echo "lading: first run — creating venv + editable install (one time)…"
  python3 -m venv "$ROOT/.venv"
  "$ROOT/.venv/bin/pip" -q install -e "$ROOT"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/lading-demo.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

step() {
  local label="$1"
  shift
  echo
  echo "── $label"
  echo "   repo:        $*"
  set +e
  "$@" 2>&1
  local rc=$?
  set -e
  echo "   exit: $rc"
}

step "the tool itself" "$LADING" --version

step "rules catalog — every rule id, how loud it is, what it catches" \
  "$LADING" rules

step "scan skills (abilities + their scripts); fail even on MED findings:" \
  "$LADING" agents "$FIX/skills" --fail-on med

step "same skills, clean dir, machine output (--json) — the Receipt itself:" \
  "$LADING" agents "$FIX/skills/clean" --json

cp .lading/receipt.json "$WORK/clean.json"

step "takeout — drop threads matching a regex, redact secrets, write a new zip:" \
  "$LADING" takeout "$FIX/takeouts/sample.zip" --drop 'project acme' --out "$WORK/chat.clean.zip"

step "repo — static audit of a git tree with no lockfile and no runnable README:" \
  "$LADING" repo "$FIX/repos/unreproducible"

cp .lading/receipt.json "$WORK/repo.json"

step "diff — what changed between two runs (added/removed by id + artifact):" \
  "$LADING" diff "$WORK/clean.json" "$WORK/repo.json"

step "report — render the receipt into a single-file, no-JS HTML report:" \
  "$LADING" report .lading/receipt.json --out "$WORK/report.html"

echo
echo "Demo done. Here is the receipt the last run left behind."
echo "Nothing else was written anywhere — $WORK is already deleted."