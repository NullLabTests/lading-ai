from __future__ import annotations

from lading.model import Finding


def attachment_finding(relpath: str) -> Finding:
    return Finding(
        "HAS-ATTACHMENT",
        "med",
        relpath,
        "takeout entry carries an attachment or file payload",
    )


def system_prompt_finding(relpath: str) -> Finding:
    return Finding(
        "HAS-SYSTEM-PROMPT",
        "med",
        relpath,
        "takeout entry embeds a system prompt",
    )


def dropped_finding(relpath: str, pattern: str) -> Finding:
    return Finding(
        "DROPPED-THREAD",
        "ok",
        relpath,
        f"thread/message dropped (--drop matched '…{pattern[:40]}')",
    )


def redacted_finding(relpath: str, count: int) -> Finding:
    return Finding(
        "REDACTED-SECRET",
        "ok",
        relpath,
        f"{count} secret-shaped string(s) replaced with [REDACTED]",
    )


def format_finding(relpath: str, fmt: str) -> Finding:
    return Finding("TAKEOUT-FORMAT", "ok", relpath, f"detected takeout format: {fmt}")


def kept_summary(relpath: str, threads: int) -> Finding:
    return Finding("KEPT-THREADS", "ok", relpath, f"{threads} thread(s) carried into cleaned archive")