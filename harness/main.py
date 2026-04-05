from __future__ import annotations

import argparse

from .audit import run_capability_audit
from .capability_registry import CAPABILITIES, build_capability_backlog
from .query_engine import EmailAgentQueryEngine
from .request_router import EmailAgentRouter
from .system_manifest import build_system_manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Email agent architecture workspace")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("summary", help="Render a Markdown summary of the email agent architecture")
    subparsers.add_parser("manifest", help="Print the current system manifest")
    subparsers.add_parser("audit", help="Run a capability audit over skills and MCP tool surface")
    capabilities = subparsers.add_parser("capabilities", help="List registered capabilities")
    capabilities.add_argument("--limit", type=int, default=20)
    route = subparsers.add_parser("route", help="Route a prompt across the capability surface")
    route.add_argument("prompt")
    route.add_argument("--limit", type=int, default=5)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "summary":
        print(EmailAgentQueryEngine.from_workspace().render_summary())
        return 0
    if args.command == "manifest":
        print(build_system_manifest().to_markdown())
        return 0
    if args.command == "audit":
        print(run_capability_audit().to_markdown())
        return 0
    if args.command == "capabilities":
        backlog = build_capability_backlog()
        for line in backlog.summary_lines()[: args.limit]:
            print(line)
        return 0
    if args.command == "route":
        matches = EmailAgentRouter().route(args.prompt, limit=args.limit)
        if not matches:
            print("No capability matches found.")
            return 0
        for item in matches:
            print(f"{item.kind}\t{item.name}\t{item.score}\t{item.reason}")
        return 0
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
