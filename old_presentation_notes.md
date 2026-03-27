# Email Agent — Presentation Notes

---

## The Problem We Are Solving

Email remains the single largest attack surface for phishing, social engineering, and malware delivery. Traditional rule-based filters catch well-known patterns, but sophisticated threats — carefully crafted phishing lures, spoofed authentication headers, malicious attachments dressed as legitimate business correspondence — increasingly slip through. At the same time, static filters are brittle: they do not learn, do not explain their reasoning, and cannot adapt to novel threat patterns without manual rule updates.

Our goal is to build an **AI-native email agent** that treats email classification not as a one-shot rule lookup, but as a reasoning loop. The agent reads an incoming email, selects the most appropriate analytical skill from a curated library, executes it, and evaluates the result. If the confidence in the classification outcome is not high enough, the agent does not give up — it loops back, selects a different or complementary skill, and tries again. The process continues until the agent is confident enough to act, or until the evidence from multiple skills converges on a verdict.

This approach mirrors how a human security analyst works: gathering signals from multiple sources, cross-referencing them, and forming a judgment only when the picture is clear.

---

## Architecture: The Skill Model

Every analytical capability in this system is packaged as a **skill** — a self-contained unit that exposes a consistent interface:

- **Name** — a unique identifier the agent uses to refer to it
- **Description** — plain-language explanation of what the skill does and when to use it
- **Input schema** — typed, validated specification of what the skill needs to run
- **Execution logic** — the actual implementation: an API call, an LLM prompt, a rule engine
- **Output schema** — structured, typed result the agent can reason over
- **Error handling** — explicit classification of failures (connection error, validation error, etc.) with a `retryable` flag so the agent knows whether to try again

This uniform interface is what makes the agent composable. The agent does not need to know how a skill works internally — only what it accepts and what it returns. Skills can be added, swapped, or upgraded without touching the agent loop.

---

## Where We Are Right Now

The foundational infrastructure is complete. The skill base classes (`BaseSkill`, `SkillResult`, `SkillMeta`, `SkillError`) are implemented and provide a generic, reusable scaffold for any skill we build going forward.

Our first production skill — **`rspamd_scan_email`** — has been fully implemented and is packaged and ready to ship. It integrates with [Rspamd](https://rspamd.com/), the industry-standard open-source spam filtering system, via its `/checkv2` HTTP endpoint. The skill:

- Accepts a raw RFC 822 email along with optional SMTP envelope metadata (sender, recipients, client IP, HELO string)
- Posts it to Rspamd and receives a rich JSON verdict containing a spam score, a recommended action, and a detailed breakdown of every rule that fired
- Normalizes the raw Rspamd output into an agent-friendly `RspamdNormalizedResult`: a risk level (`low` / `medium` / `high`), semantic categories (phishing, authentication issue, suspicious links, attachment risk, etc.), ranked symbol evidence, a plain-language summary, and a list of recommended next skills to invoke

The normalization layer is particularly important: it translates Rspamd's low-level rule names (e.g. `DMARC_POLICY_REJECT`, `PHISHING`, `BAYES_SPAM`) into structured signals the agent can act on without needing to understand Rspamd internals.

---

## What Is MCP and Why We Use It

**MCP (Model Context Protocol)** is an open standard that defines how AI models and agents communicate with external tools and data sources. Think of it as a universal adapter layer: instead of writing custom integration code every time you want to connect a new AI model to a new capability, you expose the capability once as an MCP tool, and any MCP-compatible model can use it immediately.

We have already wrapped the `rspamd_scan_email` skill as an MCP tool and the MCP server is live, running over stdio transport using the `FastMCP` framework. The exposed tool accepts the same parameters as the underlying skill and returns the fully normalized result.

The reason we chose MCP is forward compatibility. The AI model landscape is evolving rapidly — what is state-of-the-art today may be superseded in months. By exposing our skills through MCP rather than hardcoding calls to any specific model API, we ensure that any future model — whether it is a newer Gemini release, a Claude update, an open-source alternative, or a model we have not heard of yet — can plug directly into our skill library without any changes to the skills themselves. Our investment in skill development compounds over time rather than becoming model-specific technical debt.

---

## Skills: Current and Planned

**Currently implemented:**

| Skill | Description |
|---|---|
| `rspamd_scan_email` | Scans a raw email with Rspamd and returns normalized spam/phishing/security signals including risk level, categories, and matched rules |

**Planned skills (natural extensions of the current architecture):**

| Skill | Purpose |
|---|---|
| `url_reputation_check` | Resolves and checks URLs found in the email body against reputation feeds and sandboxes |
| `email_header_auth_check` | Deep inspection of SPF, DKIM, and DMARC authentication chains |
| `attachment_analyzer` | Static and dynamic analysis of email attachments for malicious content |
| `llm_phishing_reasoner` | LLM-based semantic analysis — reads the email as a human would, identifying social engineering tactics, urgency cues, and impersonation attempts |

The current Rspamd normalization layer already recommends which of these skills to invoke next based on what it detects, creating a natural signal chain between skills.

---

## Next Step: Gemini 2.5 Flash Test Run

With the Rspamd skill packaged and the MCP server running, our immediate next step is to run the first end-to-end test of the agent loop using **Gemini 2.5 Flash** as the agent model.

Gemini 2.5 Flash will connect to our MCP server, receive a raw email, invoke `rspamd_scan_email` as a tool call, interpret the normalized result, and produce a classification verdict with a confidence assessment. This test run will validate the full pipeline: skill invocation, result normalization, MCP transport, and model-side reasoning over structured security signals.

This is the moment where the individual components — the skill model, the normalization layer, the MCP server — come together as a working system.

---

## Summary

We are building a composable, model-agnostic email security agent. The skill-based architecture keeps capabilities modular and testable. MCP ensures we are never locked into a single AI provider. Rspamd gives us a battle-tested first signal. And the confidence-driven loop means the agent keeps working until it has a reliable answer.

The foundation is in place. The first skill is shipped. The server is up. Next: we run it.

---

## System Diagram: How Everything Fits Together

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          INCOMING EMAIL                                 │
│                    (raw RFC 822 + SMTP metadata)                        │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         AI AGENT LOOP                                   │
│                      (e.g. Gemini 2.5 Flash)                            │
│                                                                         │
│   1. Read email                                                         │
│   2. Select next skill to invoke  ◄────────────────────────────┐        │
│   3. Call skill via MCP                                         │        │
│   4. Evaluate result + confidence                               │        │
│   5. Confidence sufficient? ──── NO ───────────────────────────┘        │
│                    │                                                     │
│                   YES                                                    │
│                    │                                                     │
│                    ▼                                                     │
│            Final verdict + explanation                                   │
└──────────────────────┬──────────────────────────────────────────────────┘
                       │ tool calls (JSON over stdio)
                       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          MCP SERVER                                     │
│                    (FastMCP, stdio transport)                            │
│                                                                         │
│   • Translates MCP tool calls → skill inputs                            │
│   • Translates skill outputs  → MCP tool results                        │
│   • Model-agnostic: any MCP-compatible agent can connect                │
└──────────────────────┬──────────────────────────────────────────────────┘
                       │ Python method calls
                       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        SKILL LIBRARY                                    │
│                                                                         │
│  Each skill follows the same structure:                                 │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  name          — unique identifier used by the agent              │  │
│  │  description   — plain-language "when to use me" hint             │  │
│  │  input schema  — typed, validated (Pydantic)                      │  │
│  │  execution     — API call / LLM prompt / rule engine              │  │
│  │  output schema — structured result the agent reasons over         │  │
│  │  error info    — failure type + retryable flag                    │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  ┌──────────────────────┐   ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐   │
│  │  rspamd_scan_email   │     url_reputation_check    (planned)        │
│  │  [LIVE]              │   │ email_header_auth_check  (planned)  │   │
│  │                      │     attachment_analyzer      (planned)       │
│  │  POST /checkv2  ──►  │   │ llm_phishing_reasoner    (planned)  │   │
│  │  Rspamd instance     │    ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─    │
│  │        │             │                                               │
│  │        ▼             │                                               │
│  │  normalize_result()  │                                               │
│  │        │             │                                               │
│  │        ▼             │                                               │
│  │  RspamdNormalizedResult                                              │
│  │  • risk_level        │                                               │
│  │  • categories        │                                               │
│  │  • symbols/evidence  │                                               │
│  │  • recommended_      │                                               │
│  │    next_skills  ─────┼──────────► hints agent which skill to        │
│  │                      │            invoke in the next loop iteration  │
│  └──────────────────────┘                                               │
└─────────────────────────────────────────────────────────────────────────┘

Key relationships
─────────────────
  AI Agent  ←──MCP protocol──►  MCP Server  ←──Python──►  Skill Library
  Skill Library  ──────────────────────────────────────►  External APIs
                                                           (Rspamd, URL
                                                            feeds, etc.)
  recommended_next_skills  ──────────────────────────────►  Agent loop
  (output of one skill)                                    (drives next
                                                            skill pick)
```
