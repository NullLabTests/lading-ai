from __future__ import annotations

from lading.adapters.takeout_common import (
    Thread,
    deep_text,
    json_entry,
)

from lading.rules.takeout import attachment_finding, system_prompt_finding


def collect(name: str, data: bytes, run) -> None:
    """Parse a Claude export file.

    Handles the flat `conversations/{uuid}.json` (one conversation per file)
    and `conversations.json` (array of conversations).
    """
    obj = json_entry(data)
    if isinstance(obj, list):
        run.add_format("claude")
        pf = run.file_for(name, array=True)
        _collect_list(obj, name, pf, run)
        return
    if isinstance(obj, dict):
        run.add_format("claude")
        pf = run.file_for(name, array=False)
        _collect_one(obj, name, 0, pf, run)
        return


def _collect_list(lst: list, name: str, pf, run) -> None:
    for i, conv in enumerate(lst):
        if isinstance(conv, dict):
            _collect_one(conv, name, i, pf, run)


def _collect_one(conv: dict, name: str, i: int, pf, run) -> None:
    title = str(conv.get("name") or conv.get("title") or conv.get("uuid", "")[:8])
    texts = deep_text(conv)
    has_att, has_sys = _inspect(conv)
    t = Thread(file=name, index=i, title=title, obj=conv, texts=texts, has_attachment=has_att, has_system_prompt=has_sys)
    pf.threads.append(t)
    if has_att:
        run.report.findings.append(attachment_finding(f"{name} [{title}]"))
    if has_sys:
        run.report.findings.append(system_prompt_finding(f"{name} [{title}]"))


def _inspect(conv: dict) -> tuple[bool, bool]:
    has_att = False
    has_sys = False
    if conv.get("system"):
        has_sys = True
    for msg in conv.get("chat_messages") or []:
        if not isinstance(msg, dict):
            continue
        role = msg.get("role")
        if role == "system":
            has_sys = True
        content = msg.get("content") or []
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    if block.get("type") in ("image", "file", "document"):
                        has_att = True
        if role in ("tool",) or (isinstance(content, dict) and content.get("type") in ("tool_result", "tool_use")):
            if isinstance(content, dict) and content.get("content"):
                has_att = True
    return has_att, has_sys