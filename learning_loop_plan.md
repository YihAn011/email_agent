# Learning Loop Implementation Plan - Email Security Agent

## Concept

Prompt-based reinforcement: the agent reads a `learning.md` memory file before every classification. Users flag wrong predictions via a `questionary` CLI. Feedback is processed into pattern notes in `learning.md` and hard rules in `rules.yaml`. Over time, both files grow richer and the agent makes fewer repeat mistakes.

This is not weight fine-tuning - it's context-augmented inference: the agent's system prompt is extended with accumulated knowledge so it reasons differently on similar inputs.

---

## New Files

```text
email_agent/
  learning/
    learning.md
    rules.yaml
    feedback_log.jsonl
    updater.py
  cli/
    feedback.py
    rules_editor.py
    flag_command.py
```

Modified files proposed by this plan:
- `skills/imap_monitor/skill.py`
- `mcp_server.py`
- agent runner / CLI entrypoints

---

## learning.md Structure

The file is append-only. The agent reads the full file as context.

```markdown
# Agent Learning Memory

Last updated: 2026-04-04

## False Positive Patterns  HIGH WEIGHT

- [2026-04-04] Sender: boss@company.com | Subject: "Q1 budget review"
  Agent verdict: PHISHING
  Actual: LEGITIMATE
  Lesson: urgency_check over-fires on internal corporate language; cross-check sender domain
  Skills that misfired: urgency_check

## False Negative Patterns

- [2026-04-04] Sender: support@paypa1.com | Subject: "Confirm your account"
  Agent verdict: LEGITIMATE
  Actual: PHISHING
  Lesson: always run url_reputation_check when sender domain has digit substitutions
  Skills that should have caught it: url_reputation_check

## Observed Reliable Patterns

- rspamd score > 10 combined with DMARC failure is a strong phishing signal
- Urgency language alone is not sufficient for phishing verdict if sender domain is whitelisted
- Shopify/newsletter domains frequently trigger urgency_check falsely

## Sender-Specific Notes
- columbia.edu domains: consistently legitimate
- no-reply@shopify.com: marketing emails, not phishing even with urgency phrasing

## Skill Reliability Notes
- urgency_check: tends to over-fire on internal corporate language
- url_reputation_check: highly reliable when phishing_score > 0.7
```

---

## rules.yaml Structure

Pre-filter applied before the agent runs any skills. Hard rules override the agent.

```yaml
whitelist:
  senders:
    - boss@company.com
  domains:
    - columbia.edu
    - shopify.com
  subjects_containing: []

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

1. The agent classifies an email and shows the verdict in the CLI.
2. The user flags the verdict as wrong.
3. Feedback is written to `feedback_log.jsonl`.
4. `updater.py` converts feedback into `learning.md` entries and `rules.yaml` updates.
5. Future classifications read this context before reasoning.

Suggested feedback fields:
- mistake type: false positive / false negative
- skills that misfired
- actual email nature
- optional whitelist / blacklist update
- optional operator notes

---

## feedback_log.jsonl Entry Format

```json
{
  "timestamp": "2026-04-04T10:23:00Z",
  "type": "false_positive",
  "email_uid": 12345,
  "sender": "boss@company.com",
  "subject": "Q1 budget review - urgent",
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

Before every classification:

1. Apply `rules.yaml`
2. Inject the most relevant parts of `learning.md` into the system prompt
3. Run normal tool-assisted analysis

False positive history should appear first because avoiding repeat false positives is a high-priority requirement.

---

## Rules Editor

Suggested CLI:

```text
View current whitelist / blacklist
Add sender to whitelist
Add domain to blacklist
Add a custom rule
Remove an entry
View all rules
Exit
```

---

## Weighting

| Feedback Type | Weight | Prompt Priority |
|---------------|--------|-----------------|
| False positive | High | First |
| False negative | Normal | After FP context |

Rationale: false positives directly block legitimate mail, so they should carry stronger corrective pressure.

---

## Phased Implementation

### Phase 1 - Feedback Collection
- Build CLI feedback flow
- Create append-only `feedback_log.jsonl`
- Wire a flag action into the main CLI

### Phase 2 - learning.md Updater
- Build `learning.md` with fixed sections
- Create `updater.py`
- Convert raw feedback into structured learning notes

### Phase 3 - Agent Context Injection
- Read `learning.md`
- Parse sections
- Inject prioritized context into the system prompt

### Phase 4 - Pre-filter Rules
- Implement `rules.yaml`
- Add whitelist / blacklist / override evaluation before normal analysis

### Phase 5 - Rules Editor CLI
- Build a small interactive CLI for managing rules

---

## Demo Flow

1. Run on a known phishing sample
2. Run on a legitimate email that gets misclassified
3. Flag it
4. Show `learning.md` update
5. Re-run a similar email and show improved behavior
6. Show `rules.yaml` change for an explicit whitelist case
