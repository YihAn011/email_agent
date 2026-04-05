from __future__ import annotations

from collections import Counter
from pathlib import Path

from .models import EmailAgentManifest, Subsystem

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def build_system_manifest(project_root: Path | None = None) -> EmailAgentManifest:
    root = project_root or PROJECT_ROOT
    files = [
        path
        for path in root.rglob("*.py")
        if path.is_file()
        and ".venv" not in path.parts
        and "__pycache__" not in path.parts
        and ".git" not in path.parts
    ]
    tracked_roots = {"skills", "examples", "harness"}
    counter = Counter()
    for path in files:
        rel = path.relative_to(root)
        counter[rel.parts[0] if rel.parts and rel.parts[0] in tracked_roots else rel.name] += 1

    notes = {
        "chatbot.py": "top-level terminal launcher",
        "mcp_server.py": "MCP tool surface and stdio server entrypoint",
        "skills": "email analysis and IMAP monitoring implementations",
        "examples": "interactive and single-turn agent entrypoints",
        "harness": "explicit architecture layer: registry, routing, runtime, manifest, and audit",
        "imap_monitor_daemon.py": "background IMAP mailbox polling daemon",
    }
    subsystems = tuple(
        Subsystem(
            name=name,
            path=f"{name}" if name.endswith(".py") else f"{name}/",
            file_count=count,
            notes=notes.get(name, "support module"),
        )
        for name, count in counter.most_common()
    )
    return EmailAgentManifest(
        project_root=root,
        total_python_files=len(files),
        subsystems=subsystems,
    )
