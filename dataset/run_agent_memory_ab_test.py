from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import re
import sys
import time
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import dotenv
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent

csv.field_size_limit(sys.maxsize)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

dotenv.load_dotenv(PROJECT_ROOT / ".env")

from examples.model_factory import build_chat_model, resolve_default_model, resolve_provider
from harness.runtime import MCP_SERVER_PATH, build_mcp_env, render_content

DEFAULT_INPUT = PROJECT_ROOT / "dataset" / "processed" / "spam_binary_test.csv"
DEFAULT_OUTPUT = PROJECT_ROOT / "dataset" / "reports" / "agent_memory_ab_test_100.jsonl"
DEFAULT_REPORT = PROJECT_ROOT / "dataset" / "reports" / "agent_memory_ab_test_100_report.md"

BASE_TOOL_NAMES = {
    "rspamd_scan_email",
    "email_header_auth_check",
    "urgency_check",
    "url_reputation_check",
}

MEMORY_TOOL_NAMES = {
    "list_error_patterns",
    "error_pattern_memory_check",
}

NO_MEMORY_SYSTEM = """You are an email security analyst.

Classify the raw RFC822 email as exactly one of:
- benign
- suspicious
- phishing_or_spoofing

You do not have access to memory tools. Use any available non-memory security tools only if you need them.
Do not infer from labels or filenames.
Return only one JSON object with this schema:
{"verdict":"benign|suspicious|phishing_or_spoofing","confidence":"low|medium|high","reason":"short reason"}
"""

WITH_MEMORY_SYSTEM = """You are an email security analyst with access to pattern memory.

Classify the raw RFC822 email as exactly one of:
- benign
- suspicious
- phishing_or_spoofing

Required workflow:
1. Call list_error_patterns before the normal security tools.
2. Use any normal security tools only if you need them. Do not infer from labels or filenames.
3. Call error_pattern_memory_check if you have enough provisional signal fields for it.
4. Incorporate the memory result into the final verdict.

You must call both memory tools before answering.
Return only one JSON object with this schema:
{"verdict":"benign|suspicious|phishing_or_spoofing","confidence":"low|medium|high","reason":"short reason"}
"""


def clean_header(value: str, fallback: str) -> str:
    text = (value or "").replace("\r", " ").replace("\n", " ").strip()
    return text or fallback


def build_raw_email(row: dict[str, str], *, max_email_chars: int) -> str:
    msg = EmailMessage()
    msg["From"] = clean_header(row.get("sender", ""), "unknown@example.com")
    msg["To"] = clean_header(row.get("receiver", ""), "recipient@example.com")
    if row.get("date"):
        msg["Date"] = clean_header(row["date"], "")
    msg["Subject"] = clean_header(row.get("subject", ""), "(no subject)")
    msg["Message-ID"] = (
        f"<agent-abtest-{row.get('source','unknown')}-"
        f"{row.get('source_record_id','0')}@email-agent.local>"
    )

    body = row.get("email_text") or ""
    if max_email_chars > 0 and len(body) > max_email_chars:
        body = body[:max_email_chars] + "\n\n[Email body truncated for benchmark token budget.]"
    msg.set_content(body)
    return msg.as_string()


def load_random_rows(path: Path, *, sample_size: int, seed: int) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8", errors="ignore") as handle:
        rows = list(csv.DictReader(handle))
    if sample_size > len(rows):
        raise ValueError(f"Requested {sample_size} rows, but input only has {len(rows)} rows.")

    import random

    rng = random.Random(seed)
    sampled = rng.sample(rows, sample_size)
    for idx, row in enumerate(sampled, 1):
        row["_sample_index"] = str(idx)
    return sampled


def extract_final_text(messages: list[Any]) -> str:
    for message in reversed(messages):
        if isinstance(message, AIMessage):
            return render_content(message.content)
    return ""


def parse_verdict(text: str) -> tuple[str | None, str | None]:
    candidates = re.findall(r"\{.*?\}", text, flags=re.DOTALL)
    for candidate in reversed(candidates):
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        verdict = str(payload.get("verdict") or payload.get("classification") or "").strip().lower()
        if verdict == "phishing":
            verdict = "phishing_or_spoofing"
        if verdict == "spam":
            verdict = "suspicious"
        confidence = str(payload.get("confidence", "")).strip().lower() or None
        if verdict in {"benign", "suspicious", "phishing_or_spoofing"}:
            return verdict, confidence

    lowered = text.lower()
    if "phishing_or_spoofing" in lowered or "phishing" in lowered or "spoof" in lowered:
        return "phishing_or_spoofing", None
    if "suspicious" in lowered or "spam" in lowered:
        return "suspicious", None
    if "benign" in lowered or "legitimate" in lowered:
        return "benign", None
    return None, None


def predicted_binary(verdict: str | None) -> int | None:
    if verdict is None:
        return None
    return 0 if verdict == "benign" else 1


def summarize_metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "invalid": 0}
    elapsed_ms: list[int] = []
    tool_counts: list[int] = []

    for record in records:
        if record.get("elapsed_ms") is not None:
            elapsed_ms.append(int(record["elapsed_ms"]))
        tool_counts.append(len(record.get("tools_called") or []))

        actual = record["actual_binary"]
        pred = record.get("predicted_binary")
        if pred is None:
            counts["invalid"] += 1
        elif actual == 1 and pred == 1:
            counts["tp"] += 1
        elif actual == 0 and pred == 0:
            counts["tn"] += 1
        elif actual == 0 and pred == 1:
            counts["fp"] += 1
        elif actual == 1 and pred == 0:
            counts["fn"] += 1

    valid = counts["tp"] + counts["tn"] + counts["fp"] + counts["fn"]
    total = valid + counts["invalid"]
    negatives = counts["tn"] + counts["fp"]
    positives = counts["tp"] + counts["fn"]
    predicted_positive = counts["tp"] + counts["fp"]

    return {
        **counts,
        "total": total,
        "valid": valid,
        "accuracy": (counts["tp"] + counts["tn"]) / valid if valid else None,
        "fpr": counts["fp"] / negatives if negatives else None,
        "recall": counts["tp"] / positives if positives else None,
        "precision": counts["tp"] / predicted_positive if predicted_positive else None,
        "fnr": counts["fn"] / positives if positives else None,
        "avg_seconds_per_email": (sum(elapsed_ms) / len(elapsed_ms) / 1000) if elapsed_ms else None,
        "avg_tool_calls": (sum(tool_counts) / len(tool_counts)) if tool_counts else None,
    }


def metric_text(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.4f}"


async def build_agent(*, provider: str, model_name: str, rspamd_base_url: str, ollama_base_url: str, use_memory: bool):
    model = build_chat_model(
        provider=provider,
        model_name=model_name,
        temperature=0,
        ollama_base_url=ollama_base_url,
    )
    server_config = {
        "email-security": {
            "transport": "stdio",
            "command": sys.executable,
            "args": [str(MCP_SERVER_PATH)],
            "cwd": str(PROJECT_ROOT),
            "env": build_mcp_env(rspamd_base_url),
        }
    }
    client = MultiServerMCPClient(server_config)
    tools = await client.get_tools()
    allowed = BASE_TOOL_NAMES | (MEMORY_TOOL_NAMES if use_memory else set())
    tools = [tool for tool in tools if tool.name in allowed]
    return create_react_agent(model=model, tools=tools)


async def run_one(
    *,
    agent: Any,
    mode: str,
    row: dict[str, str],
    raw_email: str,
    timeout_seconds: int,
    max_retries: int,
) -> dict[str, Any]:
    system_prompt = WITH_MEMORY_SYSTEM if mode == "with_memory" else NO_MEMORY_SYSTEM
    final_result: dict[str, Any] | None = None

    for attempt in range(max_retries + 1):
        retry_note = ""
        if attempt:
            if mode == "with_memory":
                retry_note = (
                    "\n\nPrevious attempt did not call the required memory tools. "
                    "Call list_error_patterns before answering."
                )
            else:
                retry_note = ""

        user_prompt = (
            "Analyze this raw RFC822 email and return the requested JSON verdict."
            f"{retry_note}\n\n"
            f"Subject: {row.get('subject') or ''}\n"
            f"From: {row.get('sender') or ''}\n\n"
            f"{raw_email}"
        )

        started = time.perf_counter()
        try:
            result = await asyncio.wait_for(
                agent.ainvoke(
                    {"messages": [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)]},
                    config={"recursion_limit": 18},
                ),
                timeout=timeout_seconds,
            )
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            messages = result.get("messages", [])
            final_text = extract_final_text(messages)
            verdict, confidence = parse_verdict(final_text)
            tools_called = [message.name for message in messages if isinstance(message, ToolMessage)]
            error = None
        except Exception as exc:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            final_text = ""
            verdict = None
            confidence = None
            tools_called = []
            error = f"{exc.__class__.__name__}: {exc}"

        required_tools = MEMORY_TOOL_NAMES if mode == "with_memory" else BASE_TOOL_NAMES
        if mode == "with_memory":
            tool_requirement_met = bool(set(tools_called) & MEMORY_TOOL_NAMES)
        else:
            tool_requirement_met = not bool(set(tools_called) & MEMORY_TOOL_NAMES)

        final_result = {
            "mode": mode,
            "sample_index": int(row["_sample_index"]),
            "source": row.get("source", ""),
            "source_record_id": row.get("source_record_id", ""),
            "subject": row.get("subject", ""),
            "sender": row.get("sender", ""),
            "actual_binary": int(row["binary_label"]),
            "actual_label": row.get("normalized_label", ""),
            "predicted_verdict": verdict if tool_requirement_met else None,
            "predicted_binary": predicted_binary(verdict) if tool_requirement_met else None,
            "confidence": confidence if tool_requirement_met else None,
            "elapsed_ms": elapsed_ms,
            "tools_called": tools_called,
            "memory_tools_called": [name for name in tools_called if name in MEMORY_TOOL_NAMES],
            "tool_requirement_met": tool_requirement_met,
            "required_tools": sorted(required_tools),
            "attempts": attempt + 1,
            "error": error if error else (None if tool_requirement_met else "required_tools_not_called"),
            "final_text": final_text[:2000],
        }
        if tool_requirement_met:
            break

    if final_result is None:
        raise RuntimeError("run_one completed without producing a result")
    return final_result


def write_report(
    *,
    report_path: Path,
    output_path: Path,
    provider: str,
    model_name: str,
    sample_size: int,
    seed: int,
    max_email_chars: int,
    metrics_by_mode: dict[str, dict[str, Any]],
) -> None:
    lines = [
        "# Agent Memory A/B Test",
        "",
        f"- Provider/model: {provider} / {model_name}",
        f"- Sample size: {sample_size}",
        f"- Random seed: {seed}",
        f"- Max email body chars: {max_email_chars}",
        f"- Raw results: `{output_path}`",
        "",
        "| Mode | TP | TN | FP | FN | Invalid | Accuracy | FPR | Recall | Precision | FNR | Avg seconds/email | Avg tool calls |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for mode in ("no_memory", "with_memory"):
        metric = metrics_by_mode[mode]
        lines.append(
            f"| {mode} | {metric['tp']} | {metric['tn']} | {metric['fp']} | {metric['fn']} | "
            f"{metric['invalid']} | {metric_text(metric['accuracy'])} | {metric_text(metric['fpr'])} | "
            f"{metric_text(metric['recall'])} | {metric_text(metric['precision'])} | "
            f"{metric_text(metric['fnr'])} | {metric_text(metric['avg_seconds_per_email'])} | "
            f"{metric_text(metric['avg_tool_calls'])} |"
        )
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=str(DEFAULT_INPUT))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--report", default=str(DEFAULT_REPORT))
    parser.add_argument("--sample-size", type=int, default=100)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--max-email-chars", type=int, default=6000)
    parser.add_argument("--provider", default=resolve_provider())
    parser.add_argument("--model", default=None)
    parser.add_argument("--ollama-base-url", default=os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434"))
    parser.add_argument("--rspamd-base-url", default=os.getenv("RSPAMD_BASE_URL", "http://127.0.0.1:11333"))
    args = parser.parse_args()

    provider = resolve_provider(args.provider)
    model_name = args.model or resolve_default_model(provider)
    output_path = Path(args.output)
    report_path = Path(args.report)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    rows = load_random_rows(Path(args.input), sample_size=args.sample_size, seed=args.seed)
    raw_by_index = {
        int(row["_sample_index"]): build_raw_email(row, max_email_chars=args.max_email_chars)
        for row in rows
    }

    print(
        f"Running sample_size={args.sample_size} seed={args.seed} provider={provider} model={model_name}",
        flush=True,
    )
    agents = {
        "no_memory": await build_agent(
            provider=provider,
            model_name=model_name,
            rspamd_base_url=args.rspamd_base_url,
            ollama_base_url=args.ollama_base_url,
            use_memory=False,
        ),
        "with_memory": await build_agent(
            provider=provider,
            model_name=model_name,
            rspamd_base_url=args.rspamd_base_url,
            ollama_base_url=args.ollama_base_url,
            use_memory=True,
        ),
    }

    all_results: list[dict[str, Any]] = []
    with output_path.open("w", encoding="utf-8") as out:
        for i, row in enumerate(rows, 1):
            raw_email = raw_by_index[int(row["_sample_index"])]
            for mode in ("no_memory", "with_memory"):
                result = await run_one(
                    agent=agents[mode],
                    mode=mode,
                    row=row,
                    raw_email=raw_email,
                    timeout_seconds=args.timeout_seconds,
                    max_retries=args.retries,
                )
                all_results.append(result)
                out.write(json.dumps(result, ensure_ascii=False) + "\n")
                out.flush()
                print(
                    f"[{i:03d}/{args.sample_size}] {mode} actual={result['actual_binary']} "
                    f"pred={result['predicted_binary']} tools={len(result['tools_called'])} "
                    f"elapsed={result['elapsed_ms']/1000:.1f}s",
                    flush=True,
                )

    metrics_by_mode = {
        mode: summarize_metrics([record for record in all_results if record["mode"] == mode])
        for mode in ("no_memory", "with_memory")
    }
    write_report(
        report_path=report_path,
        output_path=output_path,
        provider=provider,
        model_name=model_name,
        sample_size=args.sample_size,
        seed=args.seed,
        max_email_chars=args.max_email_chars,
        metrics_by_mode=metrics_by_mode,
    )
    print(json.dumps(metrics_by_mode, indent=2, ensure_ascii=False), flush=True)
    print(f"Wrote {output_path}", flush=True)
    print(f"Wrote {report_path}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
