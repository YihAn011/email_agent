from __future__ import annotations

from pathlib import Path

from .capability_registry import CAPABILITIES
from .models import CapabilityAudit

PROJECT_ROOT = Path(__file__).resolve().parents[1]

EXPECTED_SKILL_MODULES = (
    "skills/rspamd/skill.py",
    "skills/header_auth/skill.py",
    "skills/imap_monitor/skill.py",
    "skills/urgency/skill.py",
    "skills/url_reputation/skill.py",
)


def run_capability_audit(project_root: Path | None = None) -> CapabilityAudit:
    root = project_root or PROJECT_ROOT
    registered_skills = tuple(
        path.as_posix()
        for path in sorted((root / "skills").rglob("skill.py"))
        if path.is_file()
    )
    expected_skills = tuple((root / item).as_posix() for item in EXPECTED_SKILL_MODULES)
    expected_tools = tuple(item.name for item in CAPABILITIES if item.kind == "tool")
    registered_tools = expected_tools
    missing_skills = tuple(item for item in expected_skills if item not in registered_skills)
    missing_tools = tuple(item for item in expected_tools if item not in registered_tools)
    return CapabilityAudit(
        registered_skills=registered_skills,
        expected_skills=expected_skills,
        registered_tools=registered_tools,
        expected_tools=expected_tools,
        missing_skills=missing_skills,
        missing_tools=missing_tools,
    )

