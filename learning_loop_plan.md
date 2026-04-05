# Learning Loop Implementation Plan — Email Security Agent

## Concept

Prompt-based reinforcement: the agent reads a `learning.md` memory file before every classification. Users flag wrong predictions via a `questionary` CLI. Feedback is processed into pattern notes in `learning.md` and hard rules in `rules.yaml`. Over time, both files grow richer and the agent makes fewer repeat mistakes.

This is not weight fine-tuning — it's **context-augmented inference**: the agent's system prompt is extended with accumulated knowledge so it reasons differently on similar inputs.

---

## New Files

```
email_agent/
  learning/
    learning.md          # human-readable pattern memory (agent reads this)
    rules.yaml           # whitelist / blacklist / override rules (pre-filter)
    feedback_log.jsonl   # append-only raw feedback log (audit trail)
    updater.py           # processes new feedback → updates learning.md + rules.yaml
  cli/
    feedback.py          # questionary UI: collect false positive / negative report
    rules_editor.py      # questionary UI: view and edit rules.yaml interactively
    flag_command.py      # entry point: `flag` command wired into the main CLI
```

**Modified files:**
- `skills/imap_monitor/skill.py` — inject learning context into system prompt before agent runs
- `mcp_server.py` / agent runner — load `learning.md` + `rules.yaml` at startup

---

## learning.md Structure

The file is append-only (new entries added at the bottom of each section). The agent reads the entire file as context.

```markdown
# Agent Learning Memory

Last updated: 2026-04-04

## False Positive Patterns  ⚠️ HIGH WEIGHT
<!-- These are emails the agent wrongly flagged. Prioritize these. -->

- [2026-04-04] Sender: boss@company.com | Subject: "Q1 budget review"
  Agent verdict: PHISHING (urgency_check fired on "urgent review needed")
  Actual: LEGITIMATE — internal sender, urgency language is normal for this domain
  Lesson: urgency_check over-fires on internal corporate language; cross-check sender domain
  Skills that misfired: urgency_check

## False Negative Patterns
<!-- Emails the agent missed — let through but were actually malicious -->

- [2026-04-04] Sender: support@paypa1.com | Subject: "Confirm your account"
  Agent verdict: LEGITIMATE
  Actual: PHISHING — typosquatted domain (paypa1 not paypal)
  Lesson: always run url_reputation_check when sender domain has digit substitutions
  Skills that should have caught it: url_reputation_check

## Observed Reliable Patterns
<!-- General rules the agent has learned are trustworthy signals -->

- rspamd score > 10 combined with DMARC failure is a strong phishing signal (confirmed 3x)
- Urgency language alone is not sufficient for phishing verdict if sender domain is whitelisted
- Shopify/newsletter domains frequently trigger urgency_check falsely — treat as low signal

## Sender-Specific Notes
- columbia.edu domains: consistently legitimate, urgency language is normal
- no-reply@shopify.com: marketing emails, not phishing even with urgency phrasing

## Skill Reliability Notes
- urgency_check: tends to over-fire on internal corporate language (confidence penalty suggested)
- url_reputation_check: highly reliable when phishing_score > 0.7
```

---

## rules.yaml Structure

Pre-filter applied **before** the agent runs any skills. Hard rules override the agent.

```yaml
# Email Security Agent — Rules File
# Edit directly or use: python -m cli.rules_editor

whitelist:
  senders:
    - boss@company.com
  domains:
    - columbia.edu
    - shopify.com
  subjects_containing: []   # e.g. "Q1 budget"

blacklist:
  senders:
    - spoofed@evil.com
  domains:
    - paypa1.com
  subjects_containing: []

rules:
  - description: "Internal HR emails are always legitimate"
    if:
      sender_domain: "company.com"
      subject_contains: "review"
    then:
      override_verdict: "legitimate"
      skip_skills:
        - urgency_check

  - description: "Flag any email with wire transfer language"
    if:
      body_contains: "wire transfer"
    then:
      override_verdict: "suspicious"
      force_skills:
        - url_reputation_check
        - email_header_auth_check
```

---

## Feedback Flow

### Step 1 — Agent classifies email, shows verdict in CLI

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 VERDICT: SUSPICIOUS  (confidence: 0.81)
 From: boss@company.com
 Subject: Q1 budget review — urgent
 Skills used: rspamd_scan_email, urgency_check
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [r] Read email   [f] Flag wrong verdict   [q] Quit
```

### Step 2 — User presses `f` to flag

`questionary` UI launches inline:

```
? What kind of mistake was this?
  ❯ False positive  (flagged as spam/phishing but was legitimate)
    False negative  (marked legitimate but was actually malicious)

? Which skills fired incorrectly? (space to select, enter to confirm)
  ❯ ○ rspamd_scan_email
    ● urgency_check          ← user checks this one
    ○ email_header_auth_check
    ○ url_reputation_check

? What was the actual nature of this email?
  ❯ Legitimate internal email
    Legitimate newsletter/marketing
    Legitimate notification
    Other (type below)

? Add sender to whitelist? (boss@company.com)  (Y/n)  Y

? Any notes for the agent? (optional, press enter to skip)
  > urgency language is normal for this sender
```

### Step 3 — Feedback written and processed

1. Raw entry appended to `feedback_log.jsonl` (for audit trail)
2. `updater.py` processes the entry:
   - Appends a pattern note to the correct section in `learning.md`
   - If user confirmed whitelist/blacklist → updates `rules.yaml`
   - False positives get `⚠️ HIGH WEIGHT` marker and are prepended to their section
3. Confirmation shown: `✓ Feedback saved. learning.md updated.`

---

## feedback_log.jsonl Entry Format

One JSON object per line:

```json
{
  "timestamp": "2026-04-04T10:23:00Z",
  "type": "false_positive",
  "email_uid": 12345,
  "sender": "boss@company.com",
  "subject": "Q1 budget review — urgent",
  "agent_verdict": "suspicious",
  "actual_verdict": "legitimate",
  "skills_misfired": ["urgency_check"],
  "email_nature": "Legitimate internal email",
  "added_to_whitelist": true,
  "notes": "urgency language is normal for this sender",
  "weight": "high"
}
```

---

## How the Agent Uses Learning Context

Before every classification, the agent runner:

1. **Pre-filter check** (`rules.yaml`):
   - If sender is whitelisted → return `legitimate` immediately, skip all skills
   - If sender is blacklisted → return `suspicious` immediately, skip all skills
   - If a rule matches → apply overrides (skip/force specific skills, override verdict)

2. **Inject learning context** into system prompt:
   ```
   === LEARNED PATTERNS (from past feedback) ===
   
   ⚠️ FALSE POSITIVE HISTORY (HIGH PRIORITY — avoid repeating these):
   - urgency_check over-fires on internal corporate language from company.com
   - boss@company.com has been confirmed legitimate multiple times
   
   FALSE NEGATIVE HISTORY:
   - Typosquatted domains (e.g. paypa1.com) slipped through — always run url_reputation_check
   
   SKILL RELIABILITY NOTES:
   - urgency_check: low reliability on internal senders; weight its output less
   ==========================================
   ```

3. **Agent runs normally** with this enriched context.

The false positive section is injected first and marked HIGH PRIORITY because the user explicitly asked FPs to weigh more.

---

## `cli/rules_editor.py` — Interactive Rules Editor

Triggered by: `python -m cli.rules_editor` (or a `rules` command in the CLI)

```
? What would you like to do?
  ❯ View current whitelist / blacklist
    Add sender to whitelist
    Add domain to blacklist
    Add a custom rule
    Remove an entry
    View all rules
    Exit
```

Reads and writes `rules.yaml` directly. No database. Simple enough to also hand-edit.

---

## Weighting: False Positives vs False Negatives

| Feedback Type | Weight | Placement in learning.md | Effect on prompt |
|---------------|--------|--------------------------|------------------|
| False positive | HIGH | Top of FP section, `⚠️` marker | Listed first in injected context, labeled HIGH PRIORITY |
| False negative | NORMAL | Appended to FN section | Listed after FP context |

Rationale: a false positive means a legitimate email was blocked — directly harmful to the user. A false negative means a phishing email got through — serious but the user is at least aware of the risk. Both are recorded; FPs drive more urgent prompt emphasis.

---

## Phased Implementation

### Phase 1 — Feedback Collection
- Create `cli/feedback.py` with the full `questionary` flow
- Create `learning/feedback_log.jsonl` (empty, created on first run)
- Wire `f` keypress in the main CLI verdict display to launch feedback UI
- Write raw entry to `feedback_log.jsonl` only (no learning.md update yet)

### Phase 2 — learning.md Updater
- Create `learning/learning.md` with the section structure (empty sections)
- Create `learning/updater.py`:
  - Reads new entries from `feedback_log.jsonl`
  - Parses and appends formatted entries to the correct `learning.md` section
  - Marks FP entries with `⚠️ HIGH WEIGHT`
- Call `updater.py` automatically after each feedback submission

### Phase 3 — Agent Context Injection
- Modify the agent runner to read `learning.md` at startup
- Parse the four sections and format them into a learning context block
- Inject the block into the system prompt (FP section first, emphasized)

### Phase 4 — Pre-filter (rules.yaml)
- Create `learning/rules.yaml` with the structure above (empty lists)
- Add `apply_rules(email_metadata)` function that checks whitelist/blacklist/rules before skills run
- Wire into agent runner: if rule fires → short-circuit, skip LangGraph agent entirely, return override verdict

### Phase 5 — Rules Editor CLI
- Create `cli/rules_editor.py` with the `questionary` menu
- Expose as `python -m cli.rules_editor` or a `rules` subcommand
- When feedback UI suggests whitelist addition, call the same write function

---

## What This Looks Like in a Demo

1. Run the agent on `04_spear_phishing.eml` → verdict: PHISHING
2. Run on `02_legitimate.eml` (Columbia IT email) → verdict: SUSPICIOUS (false positive)
3. Flag it — walk through the questionary UI live
4. Show `learning.md` updated with the FP entry
5. Re-run on a similar Columbia IT email — agent now reads the FP context and returns LEGITIMATE
6. Show `rules.yaml` with `columbia.edu` whitelisted
7. Run on a third Columbia email — pre-filter fires, agent skips entirely, instant LEGITIMATE

This makes the learning loop visually demonstrable end-to-end in under 2 minutes.
