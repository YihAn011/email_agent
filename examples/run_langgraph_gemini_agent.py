from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent
for candidate in (CURRENT_DIR, PROJECT_ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from harness.prompts import build_single_turn_prompt
from harness.runtime import MCP_SERVER_PATH, SingleTurnAgentRuntime, extract_final_output, render_content
from harness.ui import configure_quiet_logging, render_chat_response, render_startup_banner
from model_factory import resolve_default_model, resolve_provider


def parse_args() -> argparse.Namespace:
    default_provider = resolve_provider()
    parser = argparse.ArgumentParser(description="Run a LangGraph agent against the local MCP server.")
    parser.add_argument("--provider", default=default_provider, choices=["ollama", "gemini"])
    parser.add_argument("--model", default=resolve_default_model(default_provider))
    parser.add_argument("--ollama-base-url", default="http://127.0.0.1:11434")
    parser.add_argument("--base-url", default="http://127.0.0.1:11333")
    parser.add_argument("--email-file")
    parser.add_argument("--headers-file")
    parser.add_argument(
        "--question",
        default="Analyze this email and decide whether it is benign, suspicious, spam, or phishing.",
    )
    parser.add_argument("--show-messages", action="store_true")
    return parser.parse_args()


def read_text_file(path: str | None) -> str | None:
    if not path:
        return None
    return Path(path).expanduser().read_text(encoding="utf-8")


async def run_agent(args: argparse.Namespace) -> None:
    runtime = SingleTurnAgentRuntime(
        provider=args.provider,
        model_name=args.model,
        rspamd_base_url=args.base_url,
        ollama_base_url=args.ollama_base_url,
    )
    await runtime.setup()
    result = await runtime.invoke(
        build_single_turn_prompt(
            args.question,
            read_text_file(args.email_file),
            read_text_file(args.headers_file),
        )
    )

    print(
        render_startup_banner(
            provider=args.provider,
            model=args.model,
            rspamd_base_url=args.base_url,
            ollama_base_url=args.ollama_base_url if args.provider == "ollama" else None,
        )
    )
    print()

    if args.show_messages:
        for message in result.get("messages", []):
            name = getattr(message, "name", "")
            prefix = f"[{message.__class__.__name__}] {name}".rstrip()
            print(prefix)
            print(render_content(message.content))
            print()
        return

    messages = result.get("messages", [])
    print(render_chat_response(messages, 0) if messages else extract_final_output(result))


def main() -> None:
    configure_quiet_logging()
    asyncio.run(run_agent(parse_args()))


if __name__ == "__main__":
    main()
