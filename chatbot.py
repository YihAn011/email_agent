from __future__ import annotations

import os
import runpy
from pathlib import Path


def load_local_env(project_root: Path) -> None:
    env_path = project_root / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if not key or key in os.environ:
            continue

        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]

        os.environ[key] = value


def main() -> None:
    project_root = Path(__file__).resolve().parent
    load_local_env(project_root)
    target = project_root / "examples" / "chat_langgraph_gemini_agent.py"
    runpy.run_path(str(target), run_name="__main__")


if __name__ == "__main__":
    main()
