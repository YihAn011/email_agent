from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Capability:
    name: str
    kind: str
    source_hint: str
    responsibility: str
    trigger_terms: tuple[str, ...] = ()
    followups: tuple[str, ...] = ()
    nested_tools: tuple[str, ...] = ()
    requires_bound_mailbox: bool = False


@dataclass(frozen=True)
class Subsystem:
    name: str
    path: str
    file_count: int
    notes: str


@dataclass(frozen=True)
class RouterMatch:
    name: str
    kind: str
    score: int
    reason: str


@dataclass(frozen=True)
class EmailAgentManifest:
    project_root: Path
    total_python_files: int
    subsystems: tuple[Subsystem, ...]

    def to_markdown(self) -> str:
        lines = [
            f"Project root: `{self.project_root}`",
            f"Total Python files: **{self.total_python_files}**",
            "",
            "Subsystems:",
        ]
        lines.extend(
            f"- `{item.name}` ({item.file_count} files) — {item.notes}"
            for item in self.subsystems
        )
        return "\n".join(lines)


@dataclass
class CapabilityBacklog:
    title: str
    capabilities: list[Capability] = field(default_factory=list)

    def summary_lines(self) -> list[str]:
        return [
            f"- {item.name} [{item.kind}] — {item.responsibility} ({item.source_hint})"
            for item in self.capabilities
        ]


@dataclass(frozen=True)
class CapabilityAudit:
    registered_skills: tuple[str, ...]
    expected_skills: tuple[str, ...]
    registered_tools: tuple[str, ...]
    expected_tools: tuple[str, ...]
    missing_skills: tuple[str, ...]
    missing_tools: tuple[str, ...]

    def to_markdown(self) -> str:
        lines = [
            "# Capability Audit",
            "",
            f"Registered skills: **{len(self.registered_skills)}/{len(self.expected_skills)}**",
            f"Registered MCP tools: **{len(self.registered_tools)}/{len(self.expected_tools)}**",
            "",
            "Missing skills:",
        ]
        lines.extend(f"- {item}" for item in self.missing_skills) if self.missing_skills else lines.append("- none")
        lines.extend(["", "Missing MCP tools:"])
        lines.extend(f"- {item}" for item in self.missing_tools) if self.missing_tools else lines.append("- none")
        return "\n".join(lines)

