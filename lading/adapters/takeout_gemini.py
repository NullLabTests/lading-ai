from __future__ import annotations

from lading.adapters.takeout_common import (
    Thread,
    deep_text,
    json_entry,
)

from lading.model import Finding


_CONV_KEYS = ("title", "name", "text", "content", "message", "user_input", "model_output", "query", "answer", "conversation")


def collect(name: str, data: bytes, run) -> None:
    """Parse a Gemini takeout JSON file (path contains 'gemini')."""
    obj = json_entry(data)
    if obj is None:
        return
    run.add_format("gemini")

    # Array-shaped: each element is a conversation.
    if isinstance(obj, list):
        pf = run.file_for(name, array=True)
        for i, conv in enumerate(obj):
            if isinstance(conv, dict):
                _one(conv, name, i, pf, run)
        return

    # Dict-shaped: possibly a wrapper holding a list of conversations.
    if isinstance(obj, dict):
        for key in ("entries", "conversations", "threads", "messages", "events"):
            v = obj.get(key)
            if isinstance(v, list) and v:
                pf = run.file_for(name, array=True)
                for i, conv in enumerate(v):
                    if isinstance(conv, dict):
                        _one(conv, name, i, pf, run)
                return
        # Otherwise: the whole object is one thread-ish payload.
        texts = deep_text(obj)
        if _looks_like_conversation(obj, texts):
            pf = run.file_for(name, array=False)
            _one(obj, name, 0, pf, run)


def _looks_like_conversation(obj: dict, texts: str) -> bool:
    if not texts.strip():
        return False
    hay = " ".join(obj.keys()).lower()
    if any(k in hay for k in _CONV_KEYS):
        return True
    # A settings/empty dump with only metadata keys is not a conversation.
    return len(obj) > 0 and any(isinstance(v, str) and len(v) > 20 for v in obj.values())


def _one(conv: dict, name: str, i: int, pf, run) -> None:
    texts = deep_text(conv)
    title = str(conv.get("title") or conv.get("name") or "<untitled>")
    t = Thread(file=name, index=i, title=title, obj=conv, texts=texts)
    if texts.strip():
        pf.threads.append(t)
    run.report.findings.append(Finding("GEMINI-ENTRY", "ok", f"{name} [{title}]", "gemini takeout payload inspected"))