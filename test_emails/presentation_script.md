# Presentation Script: Email Guardian — Modular, Context-Aware, Chatbot-Driven
### Spoken script — 7 slides (~12 minutes)

---

## Slide 1 — Where We Were

**Spoken script:**

This project is an Skill-based AI email classification agent with CLI integration in the form of a chatbot. We have a reusable skill library, an AI agent reasoning loop, IMAP inbox integration, and ML-based classification skills trained from the dataset provided in class.

The core architecture is built around a shared MCP tool surface. The agent reads the email, chooses which tools to call, and uses the tool outputs as evidence instead of hard-coded verdicts. That reasoning loop is the key innovation.

The system also supports live mailbox binding through IMAP, so it can monitor recent emails, scan incoming mail continuously, and report on the latest inbox activity.

The trained skills include the rspamd scanner, header authentication checker, urgency classifier, and URL reputation scorer. These models were developed from the class dataset and provide the four primary signal channels for the agent.

| Skill | Description |
|-------|-------------|
| `rspamd_scan_email` | Open source spam Bayesian filter using regular expressions and basic rules. First-pass scanner. Returns a score against a threshold. |
| `email_header_auth_check` | Structural component that checks for header authenticity. Checks for domain mismatches and parses SPF, DKIM, DMARC, and ARC results from the headers. |
| `urgency_check` | Trained on shared dataset. Both optimized for specificity. Logistic regression against TF-IDF. Returns urgency score between 0.0 and 1.0 and boolean verdict. |
| `url_reputation_check` | Gradient boosting classifier. Returns phishing score between 0 and 1, boolean on suspiciousness, and three-way risk level (low, medium, high). |
| `error_pattern_memory_check` | Provides context augmentation by comparing current emails against patterns from past false positives and negatives, enabling the agent to learn from historical mistakes and adjust reasoning accordingly. |
| `imap_monitor` | A background daemon that connects to a real mailbox over IMAP, automatically runs every incoming message through the full skill pipeline. Can run continuously on live email without human intervention. |

This is the baseline capability set we start from, but the architecture is designed to grow beyond these core detectors.

---

## Slide 2 — Context-Augmented Learning

**Spoken script:**

The first new feature is memory-based context augmentation. The agent now keeps an error pattern file that stores past false positives and false negatives.

Before finalizing a verdict, the agent loads that memory with prompts like `call list_error_patterns` and then verifies the current prediction with `call error_pattern_memory_check`. This is how the agent actively learns from context and previous history.

That means the system is not just replaying static rules. It compares the current email against prior mistakes, adjusts its reasoning based on similar past cases, and uses a feedback loop to improve over time.

This layer is model-agnostic: the memory and tool workflow work with any decision-maker, so the architecture can support different LLMs or reasoning engines without changing the underlying skill surface.

---

## Slide 3 — New CLI Chatbot Interface

**Spoken script:**

The second new feature is a Claude-style terminal chatbot interface. Users can interact with the agent naturally, ask it to analyze emails, and receive explanations in conversational form.

The CLI supports routes: it matches user intent to capabilities and tools, so the agent can decide whether to scan a raw email, parse headers, bind an IMAP inbox, or report on recent monitored messages.

Its outputs include concise verdicts, confidence levels, evidence summaries, and recommended next steps. It also exposes mailbox commands like `bind_imap_mailbox`, `start_imap_monitor`, `poll_imap_mailboxes_once`, `imap_monitor_status`, and `list_recent_email_results`.

That means the inbox is now bindable: the agent can connect to a mailbox, maintain monitoring state, and answer questions about the newest messages rather than only analyzing one-off inputs.

---

## Slide 4 — The HARNESS Infrastructure Layer

**Spoken script:**

You might ask: if the model itself picks which skills to call, why do we need HARNESS? That is a fair question.

The answer is this: the **model picks which skill to invoke when reasoning about a specific email**. That is the agent reasoning loop. But HARNESS is not about skill selection — HARNESS is about orchestration and interface.

HARNESS handles the framing, guidance, and presentation:

- `prompts.py` builds and manages system prompts and persona configuration. The same model behaves differently depending on the instructions we give it. HARNESS lets us swap personas and prompt strategies without touching the model code.
- `capability_registry.py` enumerates all available tools and provides usage guidance. The model *could* discover tools on its own, but it performs better with clear, documented examples of when and how to use each one.
- `runtime.py` manages the persistent MCP client lifecycle. The model cannot manage its own connections; HARNESS keeps the tool channel alive across conversation turns.
- `request_router.py` analyzes user intent and pre-routes requests intelligently. This is not about replacing the model's reasoning — it is about steering the conversation toward the most relevant capabilities before the model even sees the request.
- `ui.py` renders results conversationally. The model generates structured tool outputs; HARNESS translates those into human-friendly explanations the user can understand and act on.

Without HARNESS, you have a raw LLM with MCP tools. With HARNESS, you have a product that feels integrated, responds consistently, and guides users toward the right answers.

This is why we built it inspired by Claude Code—to show that the architecture can feel as polished and natural as a real product, not just a research prototype.

---

## Slide 5 — Model-Agnostic Architecture

**Spoken script:**

The architecture is intentionally model-agnostic. The tool library, prompts, and reasoning loop are separate from the underlying language model.

That means we can swap the decision engine without rewriting the skills. Whether the agent runs on Gemini, an open-source model, or a future provider, the same MCP tool surface and reasoning workflow remain the core.

The skill library is modular: each capability implements the same `BaseSkill` interface, exposing a consistent `run()` contract and `SkillResult` envelope. This makes it easy to add new detectors or memory tools while preserving the overall architecture.

---

## Slide 6 — Reasoning Loop Optimization

**Spoken script:**

There is also an important runtime optimization in a branch named `benchmark-groq-mcp-fix`. That branch introduces a single persistent MCP client for the chat session using `MultiServerMCPClient`, and it constructs the agent with `create_react_agent`, rather than rebuilding the client or tool surface for every email interaction.

In practice, this means the agent keeps one MCP connection alive and reuses the same tool registry across turns. That kind of optimization is exactly what can cut reasoning latency dramatically — the branch is designed to improve per-email speed by tens of seconds.

If your screenshot confirms a 20–30 second improvement per email, this is the branch responsible: it is the one that moves the system from repeated setup to a unified MCP client runtime.

---

## Slide 7 — What This Means and What Comes Next

**Spoken script:**

The system has moved from a fixed comparison experiment to a flexible, extensible platform.

It now combines trained ML detectors, IMAP mailbox monitoring, context-augmented error pattern memory, and a conversational chatbot interface. The reasoning loop is central: tools provide evidence, the agent evaluates that evidence, and memory helps the agent learn from past mistakes.

The next step is adding a semantic phishing reasoner — a structured LLM skill that reads the full email and returns a confidence score. With that added, the architecture can decide when cheaper detectors are enough and when to invoke the more expensive semantic reasoning path.

This makes the project less about a single benchmark and more about building a reusable email security reasoning platform.

---

*End of script. Estimated speaking time: ~12 minutes.*
