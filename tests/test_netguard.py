"""Static source audit: lading must never import a network client.

The hard law: urllib, requests, httpx or any socket to anything but localhost
in tests are forbidden. CI must fail if an analyzer imports a network client.
This test enforces that purely by AST — no raw substring matching, so prose in
docs/footers is never misread as a network call.
"""

from __future__ import annotations

import ast
from pathlib import Path

_FORBIDDEN_MODULES = {
    "requests",
    "urllib",
    "httpx",
    "aiohttp",
    "openai",
    "socket",
    "http",
    "websocket",
    "websockets",
    "ssl",
    "selenium",
    "tornado",
    "flask",
    "django",
}

# Calls that are unambiguously a network action when their receiver is one of
# the forbidden modules (socket.connect, requests.get, urllib.request.urlopen),
# or a bare call to a network primitive.
_NETWORK_CALL_NAMES = {"urlopen", "connect", "create_connection", "sendto", "recvfrom", "get", "post"}
_NETWORK_BARE = {"urlopen", "create_connection"}


def _module_paths():
    pkg = Path(__file__).resolve().parents[1] / "lading"
    for path in sorted(pkg.rglob("*.py")):
        yield path


def _audit(source: str) -> list[str]:
    """Return human-readable violations found in `source`."""
    out: list[str] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        out.append("<unparsable>")
        return out
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in _FORBIDDEN_MODULES:
                    out.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom) and node.module:
            top = node.module.split(".")[0]
            if top in _FORBIDDEN_MODULES:
                out.append(f"from {node.module} import ...")
        elif isinstance(node, ast.Call):
            fn = node.func
            head = None
            if isinstance(fn, ast.Name):
                head = fn.id
                if head in _NETWORK_BARE:
                    out.append(f"call {head}(...)")
            elif isinstance(fn, ast.Attribute):
                receiver = fn.value
                while isinstance(receiver, ast.Attribute):
                    receiver = receiver.value
                if isinstance(receiver, ast.Name):
                    head = receiver.id
                attr = fn.attr
                if head in _FORBIDDEN_MODULES and attr in _NETWORK_CALL_NAMES:
                    out.append(f"call {head}.{attr}(...)")
                if head in ("requests", "httpx", "aiohttp") and attr in _NETWORK_CALL_NAMES:
                    out.append(f"call {head}.{attr}(...)")
    return out


def test_no_network_imports_in_package():
    offenders: list[str] = []
    for path in _module_paths():
        for violation in _audit(path.read_text()):
            offenders.append(f"{path}: {violation}")
    assert not offenders, "network client usage found:\n" + "\n".join(offenders)


def test_no_banned_module_in_test_suite():
    """The test suite itself stays offline (fixtures are inert data, excluded)."""
    root = Path(__file__).resolve().parents[1]
    for path in sorted((root / "tests").glob("*.py")):
        violations = _audit(path.read_text())
        assert not violations, f"{path}: {violations}"


def test_no_internet_dependencies():
    """pyproject may only depend on stdlib-adjacent packages (PyYAML)."""
    root = Path(__file__).resolve().parents[1]
    pyproject = (root / "pyproject.toml").read_text()
    for bad in ("requests", "httpx", "openai", "aiohttp"):
        assert bad not in pyproject, f"pyproject.toml must not depend on {bad}"