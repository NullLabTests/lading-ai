"""Network rules: does this cargo phone home, or pipe the network into sh?"""

from __future__ import annotations

import re
from dataclasses import dataclass

from lading.model import Finding

# curl | sh  /  wget -O- | bash  /  nc ... | sh — the canonical supply-chain
# smoke test. Also `ssh` piped (could tunnel a script) —  keep to the classics.
_PIPE_TO_SH = re.compile(
    r"""\b(?:curl|wget|busybox\s+wget|nc|ncat|telnet)\b
        [^\n]*?                                                        # options/url
        \|\s*(?:sudo\s+)?(?:/bin/|/usr/bin/)?(?:ba|z|c|k|fi)?sh\b""",
    re.IGNORECASE | re.VERBOSE,
)

_CURL_LIKE = re.compile(
    r"""\b(?:curl|wget|busybox\s+wget|nc|ncat|ssh)\b""",
    re.IGNORECASE,
)

_URL = re.compile(r"""https?://[^\s'"<>|)]+""")
_JS_FETCH = re.compile(r"""\bfetch\s*\(|XMLHttpRequest|new\s+WebSocket\b""")
_PY_HTTP = re.compile(r"""\b(?:requests|httpx|urllib|aiohttp)\.[a-z_]+|socket\.socket\b""")
_FTP = re.compile(r"""\bftp://""")

# Raw IP endpoints like http://1.2.3.4/ — always notable.
_IP_URL = re.compile(r"""https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?""")


@dataclass(frozen=True)
class NetRuleSet:
    def check(self, ctx) -> list[Finding]:
        """ctx: object with .relpath, .text, .kind (script|config|doc|source)."""
        findings: list[Finding] = []
        txt = ctx.text or ""
        rel = ctx.relpath
        pipe_lo = _PIPE_TO_SH.search(txt)
        if pipe_lo:
            findings.append(
                Finding(
                    "NET-PIPE-SH",
                    "high",
                    rel,
                    f"network fetch piped straight into a shell: …{pipe_lo.group(0)[:80]}",
                )
            )
        raw = _URL.search(txt)
        if raw:
            if _IP_URL.search(txt):
                findings.append(
                    Finding("NET-RAW-URL", "high", rel, f"raw endpoint (IP-based) {_URL.search(txt).group(0)}")
                )
            elif ctx.kind in ("script", "config"):
                findings.append(
                    Finding("NET-RAW-URL", "high", rel, f"embedded URL in {ctx.kind}: {raw.group(0)}")
                )
            else:
                findings.append(
                    Finding("NET-RAW-URL", "med", rel, f"URL reference in {ctx.kind}: {raw.group(0)}")
                )
        if ctx.kind in ("script", "config"):
            if _JS_FETCH.search(txt):
                findings.append(
                    Finding("NET-JS-FETCH", "med", rel, "browser/HTTP fetch in configuration or script")
                )
            if _PY_HTTP.search(txt):
                findings.append(
                    Finding("NET-PY-CLIENT", "high", rel, "python network client (requests/urllib/socket) in script")
                )
            if _CURL_LIKE.search(txt) and not _PIPE_TO_SH.search(txt):
                findings.append(
                    Finding("NET-SHELL", "med", rel, "explicit fetch utility involved (curl/wget/nc/ssh)")
                )
            if _FTP.search(txt):
                findings.append(Finding("NET-FTP", "med", rel, "ftp:// URL in script/config"))
        return findings


def net_rules(ctx) -> list[Finding]:
    return NetRuleSet().check(ctx)