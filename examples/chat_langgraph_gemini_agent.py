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

from harness.prompts import DEFAULT_EMAIL, HELP_TEXT, build_analysis_prompt
from harness.runtime import (
    MCP_SERVER_PATH,
    EmailAgentRuntime,
    is_quota_error,
    summarize_tool_messages,
)
from harness.ui import (
    configure_quiet_logging,
    render_chat_response,
    render_error,
    render_progress_line,
    render_ready_message,
    render_startup_banner,
    render_trace,
)
from model_factory import resolve_default_model, resolve_provider


def parse_args() -> argparse.Namespace:
    default_provider = resolve_provider()
    parser = argparse.ArgumentParser(description="Run the Email Guardian chatbot in the terminal.")
    parser.add_argument("--provider", default=default_provider, choices=["ollama", "gemini", "tokenrouter"])
    parser.add_argument("--model", default=resolve_default_model(default_provider))
    parser.add_argument("--ollama-base-url", default="http://127.0.0.1:11434")
    parser.add_argument("--base-url", default="http://127.0.0.1:11333")
    parser.add_argument("--show-messages", action="store_true")
    return parser.parse_args()


def read_text_file(path_text: str) -> str:
    return Path(path_text).expanduser().read_text(encoding="utf-8")


def collect_multiline_input(kind: str) -> str:
    print(f"Paste {kind}. End with a line containing only END.")
    lines: list[str] = []
    while True:
        line = input()
        if line == "END":
            break
        lines.append(line)
    return "\n".join(lines)


def normalize_command(raw: str) -> tuple[str, str]:
    if " " not in raw.strip():
        return raw.strip(), ""
    command, arg = raw.strip().split(" ", 1)
    return command, arg.strip()


async def repl(args: argparse.Namespace) -> None:
    chat = EmailAgentRuntime(
        provider=args.provider,
        model_name=args.model,
        rspamd_base_url=args.base_url,
        ollama_base_url=args.ollama_base_url,
        show_messages=args.show_messages,
    )
    await chat.setup()

    print(
        render_startup_banner(
            provider=args.provider,
            model=args.model,
            rspamd_base_url=args.base_url,
            ollama_base_url=args.ollama_base_url if args.provider == "ollama" else None,
        )
    )
    print()
    print(render_ready_message())

    while True:
        try:
            user_input = input("\nYou> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not user_input:
            continue

        command, arg = normalize_command(user_input)

        if command in {"/quit", "/exit"}:
            print("Exiting.")
            break
        if command == "/help":
            print(HELP_TEXT)
            continue
        if command == "/reset":
            chat.reset()
            print("Conversation history cleared.")
            continue
        if command == "/trace":
            if arg not in {"on", "off"}:
                print("Usage: /trace on|off")
                continue
            chat.show_messages = arg == "on"
            print(f"Trace output {'enabled' if chat.show_messages else 'disabled'}.")
            continue

        prompt = user_input
        if command == "/sample":
            prompt = build_analysis_prompt(
                "Analyze this email and decide whether it is benign, suspicious, spam, or phishing.",
                raw_email=DEFAULT_EMAIL,
            )
        elif command == "/email-file":
            if not arg:
                print("Usage: /email-file /path/to/message.eml")
                continue
            try:
                prompt = build_analysis_prompt(
                    "Analyze this email and decide whether it is benign, suspicious, spam, or phishing.",
                    raw_email=read_text_file(arg),
                )
            except OSError as exc:
                print(f"Failed to read email file: {exc}")
                continue
        elif command == "/headers-file":
            if not arg:
                print("Usage: /headers-file /path/to/headers.txt")
                continue
            try:
                prompt = build_analysis_prompt(
                    "Analyze these headers for SPF, DKIM, DMARC, ARC, routing anomalies, and sender-domain mismatches.",
                    raw_headers=read_text_file(arg),
                )
            except OSError as exc:
                print(f"Failed to read headers file: {exc}")
                continue
        elif command == "/paste-email":
            prompt = build_analysis_prompt(
                "Analyze this email and decide whether it is benign, suspicious, spam, or phishing.",
                raw_email=collect_multiline_input("a raw RFC822 email"),
            )
        elif command == "/paste-headers":
            prompt = build_analysis_prompt(
                "Analyze these headers for SPF, DKIM, DMARC, ARC, routing anomalies, and sender-domain mismatches.",
                raw_headers=collect_multiline_input("raw email headers"),
            )

        start_idx = len(chat.history)
        try:
            print()
            messages, _ = await chat.ask(
                prompt,
                progress_callback=(lambda line: print(render_progress_line(line))),
            )
        except Exception as exc:
            tool_summary = summarize_tool_messages(chat.history, start_idx)
            print(
                render_error(
                    exc,
                    quota=is_quota_error(exc),
                    tool_summary=tool_summary,
                )
            )
            continue

        if chat.show_messages:
            print(render_trace(messages, start_idx))
            continue

        print()
        print(render_chat_response(messages, start_idx))


def main() -> None:
    configure_quiet_logging()
    asyncio.run(repl(parse_args()))


if __name__ == "__main__":
    main()
