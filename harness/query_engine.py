from __future__ import annotations

from dataclasses import dataclass

from .audit import run_capability_audit
from .capability_registry import CAPABILITIES, build_capability_backlog
from .models import EmailAgentManifest
from .system_manifest import build_system_manifest


@dataclass(frozen=True)
class EmailAgentQueryEngine:
    manifest: EmailAgentManifest

    @classmethod
    def from_workspace(cls) -> "EmailAgentQueryEngine":
        return cls(manifest=build_system_manifest())

    def render_summary(self) -> str:
        backlog = build_capability_backlog()
        audit = run_capability_audit()
        sections = [
            "# Email Agent System Summary",
            "",
            self.manifest.to_markdown(),
            "",
            f"{backlog.title}: {len(CAPABILITIES)} entries",
            *backlog.summary_lines()[:12],
            "",
            audit.to_markdown(),
        ]
        return "\n".join(sections)

