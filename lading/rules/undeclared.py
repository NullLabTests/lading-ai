from __future__ import annotations

from lading.model import Finding


def undeclared_rules(ctx) -> list[Finding]:
    """ctx: object with .skill_root, .executables (rel paths), .declared (set of rel paths).

    Flags executables that ship in a skill folder but are not listed in the
    SKILL.md frontmatter/body. A machine that runs ad-hoc sidecar scripts
    without declaring them is cargo that nobody signed for.
    """
    findings: list[Finding] = []
    executable = set(ctx.executables)
    declared = {d.replace("\\", "/").lstrip("/") for d in ctx.declared}
    for exe in sorted(executable):
        if exe not in declared:
            findings.append(
                Finding(
                    "UNDECLARED",
                    "med",
                    f"{ctx.skill_root}/{exe}",
                    f"executable script {exe!r} not listed in SKILL.md",
                )
            )
    return findings