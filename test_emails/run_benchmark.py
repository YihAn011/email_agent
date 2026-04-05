"""
Benchmark: Baseline (all 4 skills exhaustive) vs. Agentic (adaptive LLM)
Skills: rspamd_scan_email, email_header_auth_check, urgency_check, url_reputation_check
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path
from typing import Any

import dotenv
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
dotenv.load_dotenv(PROJECT_ROOT / ".env")

from examples.model_factory import build_chat_model, resolve_default_model, resolve_provider

from skills.rspamd.schemas import RspamdScanEmailInput
from skills.rspamd.skill import RspamdScanEmailSkill
from skills.header_auth.schemas import EmailHeaderAuthCheckInput
from skills.header_auth.skill import EmailHeaderAuthCheckSkill
from skills.urgency.schemas import UrgencyCheckInput
from skills.urgency.skill import UrgencyCheckSkill
from skills.url_reputation.schemas import UrlReputationInput
from skills.url_reputation.skill import UrlReputationSkill
from skills.imap_monitor.skill import _compose_final_verdict

MCP_SERVER_PATH = PROJECT_ROOT / "mcp_server.py"
RSPAMD_BASE_URL = os.getenv("RSPAMD_BASE_URL", "http://127.0.0.1:11333")

EMAILS = [
    ("01_obvious_phishing.eml",   "Obvious Phishing (QuickBooks impersonation)"),
    ("02_legitimate.eml",         "Legitimate (Columbia IT maintenance notice)"),
    ("03_ambiguous_marketing.eml","Ambiguous (Shopify flash-sale marketing)"),
    ("04_spear_phishing.eml",     "Spear Phishing (Columbia IT security alert)"),
]

SYSTEM_PROMPT = """You are an email security analyst.

You have access to MCP tools exposed by the local email security server.

Tool usage guidance:
- Use `rspamd_scan_email` when raw RFC822 email content is available and you need a scanner-backed verdict.
- Use `email_header_auth_check` when you need to inspect SPF, DKIM, DMARC, ARC, or sender-domain signals.
- Use `urgency_check` when the email may be using pressure tactics or urgency language to manipulate the recipient.
- Use `url_reputation_check` when the email contains links or when rspamd flags suspicious URL patterns.
- Chain tools as needed: start with rspamd, then call additional tools if the evidence is ambiguous or incomplete.

Response requirements:
- Start with a concise verdict and confidence level.
- Clearly separate tool evidence from your own inference.
- Mention the most important findings and recommended next step.
"""


def build_mcp_env() -> dict[str, str]:
    env = dict(os.environ)
    env.pop("PS1", None)
    env["RSPAMD_BASE_URL"] = RSPAMD_BASE_URL
    return env


# ── Baseline (exhaustive — all 4 skills always) ───────────────────────────────

def run_baseline(raw_email: str) -> dict[str, Any]:
    t0 = time.perf_counter()

    rspamd_skill  = RspamdScanEmailSkill(base_url=RSPAMD_BASE_URL)
    header_skill  = EmailHeaderAuthCheckSkill()
    urgency_skill = UrgencyCheckSkill()
    url_skill     = UrlReputationSkill()

    rspamd_result  = rspamd_skill.run(RspamdScanEmailInput(raw_email=raw_email, include_raw_result=False))
    header_result  = header_skill.run(EmailHeaderAuthCheckInput(raw_email=raw_email, include_raw_headers=False))

    # Extract body text for ML skills
    body = raw_email.split("\n\n", 1)[-1] if "\n\n" in raw_email else raw_email
    subject = ""
    for line in raw_email.splitlines():
        if line.lower().startswith("subject:"):
            subject = line[8:].strip()
            break

    urgency_result = urgency_skill.run(UrgencyCheckInput(email_text=body, subject=subject))
    url_result     = url_skill.run(UrlReputationInput(email_text=body, subject=subject))

    final_verdict, summary = _compose_final_verdict(rspamd_result, header_result)
    elapsed_ms = int((time.perf_counter() - t0) * 1000)

    rd = rspamd_result.data
    hd = header_result.data
    ud = urgency_result.data
    ld = url_result.data

    return {
        "verdict": final_verdict,
        "rspamd_score": rd.score if rd else None,
        "rspamd_required": rd.required_score if rd else None,
        "rspamd_risk": rd.risk_level if rd else None,
        "rspamd_categories": rd.categories if rd else [],
        "header_risk": hd.risk_level if hd else None,
        "header_findings": [f.type for f in hd.findings] if hd else [],
        "urgency_label": ud.urgency_label if ud else None,
        "urgency_score": ud.urgency_score if ud else None,
        "urgency_risk": ud.risk_contribution if ud else None,
        "url_phishing_score": ld.phishing_score if ld else None,
        "url_suspicious": ld.is_suspicious if ld else None,
        "url_risk": ld.risk_level if ld else None,
        "skills_called": ["rspamd_scan_email", "email_header_auth_check", "urgency_check", "url_reputation_check"],
        "summary": summary,
        "elapsed_ms": elapsed_ms,
    }


# ── Agentic (adaptive LLM) ────────────────────────────────────────────────────

async def run_agent_on_email(raw_email: str) -> dict[str, Any]:
    t0 = time.perf_counter()

    provider = resolve_provider()
    model_name = resolve_default_model(provider)
    model = build_chat_model(
        provider=provider,
        model_name=model_name,
        temperature=0,
        ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434"),
    )
    mcp_env = build_mcp_env()

    server_config = {
        "email-security": {
            "transport": "stdio",
            "command": sys.executable,
            "args": [str(MCP_SERVER_PATH)],
            "cwd": str(PROJECT_ROOT),
            "env": mcp_env,
        }
    }

    client = MultiServerMCPClient(server_config)
    tools = await client.get_tools()
    agent = create_react_agent(model=model, tools=tools)

    prompt = (
        "Analyze this email and decide whether it is benign, suspicious, spam, or phishing.\n\n"
        "Use the available MCP tools to analyze the following raw RFC822 email:\n\n"
        + raw_email
    )

    result = await agent.ainvoke({
        "messages": [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=prompt),
        ]
    })

    elapsed_ms = int((time.perf_counter() - t0) * 1000)
    messages = result.get("messages", [])
    tools_called = [m.name for m in messages if isinstance(m, ToolMessage)]

    final_text = ""
    for m in reversed(messages):
        if isinstance(m, AIMessage) and m.content:
            if isinstance(m.content, list):
                for block in m.content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        final_text = block["text"]
                        break
            elif isinstance(m.content, str):
                final_text = m.content
            if final_text:
                break

    tokens_in, tokens_out = 0, 0
    for m in messages:
        if isinstance(m, AIMessage):
            usage = getattr(m, "usage_metadata", None)
            if usage:
                tokens_in += usage.get("input_tokens", 0)
                tokens_out += usage.get("output_tokens", 0)

    return {
        "provider": provider,
        "model_name": model_name,
        "verdict_text": final_text,
        "tools_called": tools_called,
        "num_tool_calls": len(tools_called),
        "elapsed_ms": elapsed_ms,
        "tokens_input": tokens_in,
        "tokens_output": tokens_out,
    }


# ── Main ──────────────────────────────────────────────────────────────────────

async def main() -> None:
    emails_dir = Path(__file__).parent
    all_results = []

    print("=" * 60)
    print("EMAIL SECURITY BENCHMARK  (4-skill pipeline)")
    print(f"Rspamd: {RSPAMD_BASE_URL}")
    print("=" * 60)

    for i, (filename, label) in enumerate(EMAILS):
        raw_email = (emails_dir / filename).read_text(encoding="utf-8")
        print(f"\n[{label}]")

        print("  Running baseline ...", end=" ", flush=True)
        baseline = run_baseline(raw_email)
        print(f"done ({baseline['elapsed_ms']} ms)  verdict={baseline['verdict']}  urgency={baseline['urgency_label']}  url_risk={baseline['url_risk']}")

        if i > 0:
            print("  Waiting 60s for rate limit ...", end=" ", flush=True)
            await asyncio.sleep(60)
            print("done")

        print("  Running agent   ...", end=" ", flush=True)
        agent = await run_agent_on_email(raw_email)
        print(f"done ({agent['elapsed_ms']} ms)  tools={agent['tools_called']}")

        all_results.append({"label": label, "filename": filename, "baseline": baseline, "agent": agent})

        # Save incrementally so a crash doesn't lose earlier results
        write_report(all_results)
        print(f"  (partial report saved)")

    write_report(all_results)
    print("\nReport written to test_emails/benchmark_results.md")


def write_report(results: list[dict]) -> None:
    out_path = Path(__file__).parent / "benchmark_results.md"
    lines = []

    lines += [
        "# Email Security Benchmark Results",
        "",
        "**Baseline:** exhaustive — all 4 skills run on every email  ",
        f"**Agent:** {results[0]['agent']['provider']} / {results[0]['agent']['model_name']} — adaptive skill selection via MCP  " if results else "**Agent:** adaptive LLM via MCP  ",
        "**Skills available:** `rspamd_scan_email`, `email_header_auth_check`, `urgency_check`, `url_reputation_check`",
        "",
        "---",
        "",
        "## Summary Table",
        "",
        "| # | Email | Baseline Verdict | Baseline Urgency | Baseline URL Risk | Agent Tools Called | Agent Verdict | Baseline ms | Agent ms | Tokens In | Tokens Out |",
        "|---|-------|-----------------|-----------------|------------------|--------------------|---------------|-------------|----------|-----------|------------|",
    ]

    for i, r in enumerate(results, 1):
        b = r["baseline"]
        a = r["agent"]
        agent_tools = ", ".join(a["tools_called"]) if a["tools_called"] else "none"
        first_line = a["verdict_text"].split("\n")[0][:80].strip()
        lines.append(
            f"| {i} | {r['label']} | {b['verdict']} | {b['urgency_label']} ({b['urgency_score']:.2f}) | "
            f"{b['url_risk']} ({b['url_phishing_score']:.2f}) | {agent_tools} | {first_line} | "
            f"{b['elapsed_ms']} | {a['elapsed_ms']} | {a['tokens_input'] or '—'} | {a['tokens_output'] or '—'} |"
        )

    lines += ["", "---", "", "## Per-Email Detail", ""]

    for i, r in enumerate(results, 1):
        b = r["baseline"]
        a = r["agent"]
        lines += [
            f"### {i}. {r['label']}",
            f"**File:** `{r['filename']}`",
            "",
            "#### Baseline (all 4 skills)",
            f"- **Final verdict:** {b['verdict']}",
            f"- **rspamd:** score={b['rspamd_score']} / {b['rspamd_required']}  risk={b['rspamd_risk']}  categories={', '.join(b['rspamd_categories']) or 'none'}",
            f"- **header_auth:** risk={b['header_risk']}  findings={', '.join(b['header_findings']) or 'none'}",
            f"- **urgency_check:** label={b['urgency_label']}  score={b['urgency_score']}  contribution={b['urgency_risk']}",
            f"- **url_reputation:** phishing_score={b['url_phishing_score']}  suspicious={b['url_suspicious']}  risk={b['url_risk']}",
            f"- **Time:** {b['elapsed_ms']} ms  (4 skills, no LLM)",
            "",
            f"#### Agent ({a['provider']} / {a['model_name']})",
            f"- **Tools called:** {', '.join(a['tools_called']) or 'none'} ({a['num_tool_calls']} call(s))",
            f"- **Time:** {a['elapsed_ms']} ms",
            f"- **Tokens:** {a['tokens_input']} in / {a['tokens_output']} out",
            "- **Verdict:**",
            "",
            *(f"  {line}" for line in a["verdict_text"].split("\n")),
            "",
            "---",
            "",
        ]

    lines += [
        "## Comparison Charts",
        "",
        "### Latency (ms)",
        "",
        "| Email | Baseline (4 skills) | Agent |",
        "|-------|---------------------|-------|",
    ]
    for r in results:
        lines.append(f"| {r['label']} | {r['baseline']['elapsed_ms']} | {r['agent']['elapsed_ms']} |")

    lines += [
        "",
        "### Skill Calls per Email",
        "",
        "| Email | Baseline | Agent (adaptive) | Skills Agent skipped |",
        "|-------|----------|-----------------|----------------------|",
    ]
    all_skills = {"rspamd_scan_email", "email_header_auth_check", "urgency_check", "url_reputation_check"}
    for r in results:
        called = set(r["agent"]["tools_called"])
        skipped = all_skills - called
        lines.append(
            f"| {r['label']} | 4 | {r['agent']['num_tool_calls']} ({', '.join(r['agent']['tools_called']) or 'none'}) "
            f"| {', '.join(sorted(skipped)) or '—'} |"
        )

    lines += [
        "",
        "### Baseline: ML Skill Signals",
        "",
        "| Email | Urgency Label | Urgency Score | URL Phishing Score | URL Suspicious |",
        "|-------|--------------|---------------|--------------------|----------------|",
    ]
    for r in results:
        b = r["baseline"]
        lines.append(
            f"| {r['label']} | {b['urgency_label']} | {b['urgency_score']:.3f} | "
            f"{b['url_phishing_score']:.3f} | {b['url_suspicious']} |"
        )

    lines += [
        "",
        "### Token Usage (Agent only)",
        "",
        "| Email | Tokens In | Tokens Out | Total |",
        "|-------|-----------|------------|-------|",
    ]
    for r in results:
        a = r["agent"]
        total = (a["tokens_input"] or 0) + (a["tokens_output"] or 0)
        lines.append(f"| {r['label']} | {a['tokens_input'] or '—'} | {a['tokens_output'] or '—'} | {total or '—'} |")

    out_path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    asyncio.run(main())
