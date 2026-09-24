from __future__ import annotations

from lading.adapters.takeout_common import (
    Thread,
    deep_text,
    json_entry,
)

from lading.rules.takeout import attachment_finding, system_prompt_finding


def collect(name: str, data: bytes, run) -> None:
    """Parse a ChatGPT export file (conversations.json, array of conversations)."""
    obj = json_entry(data)
    if not isinstance(obj, list):
        return
    run.add_format("chatgpt")
    pf = run.file_for(name, array=True)
    seen = 0
    for i, conv in enumerate(obj):
        if not isinstance(conv, dict):
            continue
        seen += 1
        title = str(conv.get("title") or "<untitled>")
        texts = deep_text(conv)
        has_att, has_sys = _inspect(conv)
        t = Thread(file=name, index=i, title=title, obj=conv, texts=texts, has_attachment=has_att, has_system_prompt=has_sys)
        pf.threads.append(t)
        if has_att:
            run.report.findings.append(attachment_finding(f"{name} [{title}]"))
        if has_sys:
            run.report.findings.append(system_prompt_finding(f"{name} [{title}]"))
    if seen:
        run.report.findings.append(_format_note(name, seen))


def _format_note(name: str, seen: int):
    from lading.rules.takeout import format_finding

    f = format_finding(name, "chatgpt")
    return f


def _messages(conv: dict) -> list[dict]:
    """ChatGPT exports use either `messages` or a `mapping` keyed by node id."""
    msgs = conv.get("messages")
    if isinstance(msgs, list):
        return [m for m in msgs if isinstance(m, dict)]
    mapping = conv.get("mapping")
    if isinstance(mapping, dict):
        out: list[dict] = []
        for node in mapping.values():
            if isinstance(node, dict):
                msg = node.get("message")
                if isinstance(msg, dict):
                    out.append(msg)
        return out
    return []


def _inspect(conv: dict) -> tuple[bool, bool]:
    has_att = False
    has_sys = False
    for msg in _messages(conv):
        author = (msg.get("author") or {}).get("role") if isinstance(msg.get("author"), dict) else None
        if author == "system" or (isinstance(msg.get("content"), dict) and msg.get("content", {}).get("content_type") == "system"):
            has_sys = True
        ctype = msg.get("content")
        if isinstance(ctype, dict):
            parts = ctype.get("parts") or []
            for p in parts:
                if isinstance(p, dict) and ("attachment" in p or p.get("content_type") in ("image", "file")):
                    has_att = True
            if ctype.get("attachments"):
                has_att = True
        if msg.get("attachment") or msg.get("attachments"):
            has_att = True
    return has_att, has_sys