# Presentation Script: Email Guardian — Desktop App, Benchmark Results & New Skills
### Spoken script — updated for final demo (~15 minutes)

---

## Slide 1 — Where We Were (Recap)

**Spoken script:**

This project is a skill-based AI email classification agent. The core architecture is a reasoning loop: the agent reads an email, chooses which MCP tools to invoke, and uses those tool outputs as evidence to form a verdict rather than applying fixed rules.

The trained skill library includes:

| Skill | What it does |
|-------|-------------|
| `rspamd_scan_email` | Bayesian spam filter — returns a score and risk level |
| `email_header_auth_check` | Checks SPF, DKIM, DMARC, ARC, and domain mismatches |
| `urgency_check` | Logistic regression on TF-IDF — returns urgency score 0→1 |
| `url_reputation_check` | Gradient boosting — returns phishing score 0→1 and risk level |
| `error_pattern_memory_check` | Compares current email against past false positives/negatives |
| `imap_monitor` | Background daemon that monitors a live mailbox continuously |

Last session we added the web UI — a FastAPI + SSE + Vanilla JS interface that streams live skill execution as the agent runs. This session covers what Yihe built on top of that.

---

## Slide 2 — What Yihe Built: Desktop Application (3 Commits)

**Spoken script:**

Yihe made three commits this week. Together they deliver a native desktop application that replaces the browser as the front door to the agent.

**Commit 1 — `ui-pet`:** The initial desktop application built on PySide6 (Qt for Python). This commit introduced the full 1614-line `desktop_pet.py` file — the entire app from scratch. Also added the A/B memory experiment runner in `dataset/run_agent_memory_ab_test.py`.

**Commit 2 — `pet`:** Extended the app with the full launch script `scripts/start_full_stack.sh` (201 lines), which starts Redis, Rspamd or mock Rspamd, and Ollama if configured, then launches the desktop app — one command to bring up the entire stack.

**Commit 3 — `readme`:** Updated README with setup and run instructions for the new app.

The app is called **Email Guardian**. Here is what it looks like and how it works:

- A 72×72 pixel ball widget sits in the bottom-right corner of the screen, always on top of other windows. Color-coded: grey=starting, green=ready, orange=analyzing, red=error.
- Click the ball — it animates open into a 1180×680 panel with three panes: controls sidebar, inbox browser, chat.
- Click the ball inside the panel to collapse it back out of the way.

This is what we called the "desktop pet" concept: persistent, unobtrusive, always accessible.

---

## Slide 3 — Desktop App Features

**Spoken script:**

The panel has three panes working together:

**Left sidebar:** Model and provider selection (Gemini or Ollama), live switching, mailbox binding (email address, IMAP host, app password), inbox controls, and action buttons — Sample Email, Email File, Paste Email, Paste Headers, Chat View, Reset, Help.

**Middle pane — Mailbox Browser:** After binding your IMAP account, this pane loads your actual inbox paginated 10 messages at a time. You can click any message to read its full body. You can **select up to 3 messages** and click "Use Selected Emails In Chat" — the app builds a structured multi-email prompt and sends it to the agent. Each email gets its own verdict section in the response.

**Right pane — Chat:** A progress log at the top shows tool invocations in real time as the agent works. The chat history and AI response render below. Text input and Send at the bottom.

The single most interesting feature is the multi-email analysis: select three different emails, hit one button, get three separate security verdicts with evidence in one agent run.

---

## Slide 4 — Benchmark: The 4 Test Emails

**Spoken script:**

Now to the results. The benchmark was run against 4 hand-crafted test emails designed to cover the key edge cases a real inbox would surface. These are not from a public dataset — they were written to represent realistic scenarios:

| # | Email | Threat Level | Why It's Interesting |
|---|-------|-------------|----------------------|
| 1 | QuickBooks invoice phishing | Obvious phishing | Classic impersonation — easy case |
| 2 | Columbia IT maintenance notice | Legitimate | Should be benign — false positive risk |
| 3 | Shopify flash-sale marketing | Ambiguous | Urgency language but legitimate sender |
| 4 | Columbia IT security alert spear phish | Spear phishing | Sophisticated impersonation of trusted domain |

**Conditions:** Two runs per email. First run: **baseline** — all 4 skills executed deterministically on every email, no LLM, hard-coded verdict logic. Second run: **agent** — Gemini 2.5 Flash via MCP, adaptive skill selection, agent decides which tools to call and how many.

---

## Slide 5 — Results: Accuracy and Verdicts

**Spoken script:**

Here is the verdict comparison:

| Email | True Label | Baseline | Agent | Baseline Correct? | Agent Correct? |
|-------|-----------|---------|-------|-------------------|---------------|
| Obvious Phishing | phishing | phishing_or_spoofing | Phishing (high confidence) | ✓ | ✓ |
| Legitimate | benign | **phishing_or_spoofing** | Benign (high confidence) | **✗ FALSE POSITIVE** | ✓ |
| Ambiguous marketing | suspicious | phishing_or_spoofing | **Suspicious** (moderate) | Over-classified | ✓ More nuanced |
| Spear Phishing | phishing | phishing_or_spoofing | Phishing (high confidence) | ✓ | ✓ |

**Accuracy:**
- Baseline: 3/4 (75%) — misclassified the legitimate Columbia IT email as phishing
- Agent: 4/4 (100%) — correctly identified all four, including the false positive the baseline missed

**False Positive Rate:**
- Baseline: 1 out of 1 legitimate email flagged = **100% FPR** on the legitimate case
- Agent: 0 false positives = **0% FPR**

The key insight: the baseline's hard-coded logic cannot recover from a high rspamd score even when header auth confirms the email is legitimate. The agent read both signals, saw the contradiction, and reasoned that authenticated columbia.edu headers outweigh a noisy rspamd result.

---

## Slide 6 — Results: Skills Invoked

**Spoken script:**

The agent did not call all 4 skills on every email. It was selective:

| Email | Skills Agent Called | Skills Skipped |
|-------|--------------------|-|
| Obvious Phishing | `rspamd_scan_email` (1 skill) | header_auth, urgency, url_reputation |
| Legitimate | `rspamd_scan_email`, `email_header_auth_check` (2 skills) | urgency, url_reputation |
| Ambiguous marketing | All 4 skills | — |
| Spear Phishing | `rspamd_scan_email`, `email_header_auth_check` (2 skills) | urgency, url_reputation |

**Most-invoked skill: `rspamd_scan_email`** — called in all 4 runs. It is always the agent's first move; a high rspamd score is sufficient evidence for obvious phishing.

**Second most-invoked: `email_header_auth_check`** — called in 3 of 4 runs. The agent reaches for header auth whenever rspamd alone is not conclusive.

`urgency_check` and `url_reputation_check` were only invoked on the ambiguous Shopify email — the one case where all signals conflicted. The agent correctly recognized it needed more evidence before committing.

---

## Slide 7 — Results: Latency and Tokens

**Spoken script:**

There is a cost to the agent's better accuracy: time and tokens.

**Latency:**

| Email | Baseline | Agent | Ratio |
|-------|---------|-------|-------|
| Obvious Phishing | 1,881 ms | 8,476 ms | 4.5× |
| Legitimate | 51 ms | 16,015 ms | 314× |
| Ambiguous marketing | 49 ms | 64,183 ms | 1,309× |
| Spear Phishing | 49 ms | 14,483 ms | 296× |

The baseline is fast because it is pure local ML — no LLM calls, no network round-trips to the model API. The agent is slower because every tool call involves model reasoning. The Ambiguous email took over a minute because the agent called all 4 skills and still deliberated before committing to "suspicious."

**Token usage (agent only):**

| Email | Tokens In | Tokens Out | Total |
|-------|-----------|------------|-------|
| Obvious Phishing | 5,156 | 2,372 | 7,528 |
| Legitimate | 10,010 | 2,998 | 13,008 |
| Ambiguous marketing | ~12,000 | ~3,200 | ~15,200 |
| Spear Phishing | 6,947 | 2,307 | 9,254 |

Token cost scales with how many tools the agent calls and how much it deliberates. The ambiguous email cost roughly twice as many tokens as the obvious phishing case.

**The tradeoff in one sentence:** the baseline is 300× faster but produced a false positive that would have alarmed a real user about a legitimate IT email. The agent took longer but got it right.

---

## Slide 8 — Future Works

**In-App Results Dashboard**

The next milestone is closing the feedback loop between the agent's classifications and the user. We plan to add a results dashboard directly inside the desktop app — no external tools needed.

Key features:
- Select any subset of emails from your bound mailbox and run the agent across all of them in batch
- Results populate a live chart as each email finishes — verdict distribution (benign / suspicious / phishing) shown as a bar or pie chart
- Summary statistics: total analyzed, breakdown by verdict, average confidence, skills invoked per email
- Export button for the raw results

The goal is to let a user point the agent at their inbox, run it, and immediately see a visual picture of their mailbox's threat landscape — without writing any code or reading JSON.

This builds directly on the A/B memory experiment infrastructure already in `dataset/run_agent_memory_ab_test.py`, which proved the batch pipeline works. The dashboard is the user-facing version of that same capability.

---

*End of script. Estimated speaking time: ~15 minutes.*
