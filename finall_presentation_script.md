# Email Guardian — Final Presentation Script

Speakers: Yihe An, Jue Wang
Format: 15 min talk + 5 min demo
Source deck: `Email Guardian Final Presentation.pptx` (14 slides)

---

## Slide 1 — Title / Core Thesis

> Email Guardian — A conservative, skill-based email security agent evaluated on a 40,000-email benchmark.

**Speaker script (long form — read carefully):**

Good afternoon. We're Yihe An and Jue Wang, and the project we want to walk you through is called **Email Guardian**. In one sentence: it is a conservative, skill-based email-security agent that we evaluated on a 40,000-email benchmark — four model configurations, ten thousand emails each, balanced 50/50 between legitimate mail and spam/phishing.

The reason we built it the way we did comes down to a single design tension. Large language models are extremely good at reading an email and *sounding* confident about whether it is phishing. The problem is that for an email-security product, the cost of being wrong in one direction is catastrophic. If we wrongly flag legitimate mail as phishing, we block a real invoice, a real password reset, a real recruiter email — that is not a bug, that is a product killer. So we set our project goal not as "highest accuracy" but as **lowest false-positive rate while still preserving recall**.

That gives us our thesis, which is the line under our title:

> **The system should not ask an LLM to freely decide whether an email is phishing. It should combine calibrated detectors, hard evidence, and constrained LLM review only for ambiguous cases.**

Three ideas are doing work in that sentence, and the rest of this talk basically unpacks all three:

1. **"Calibrated detectors"** means we trained a content classifier whose decision threshold was specifically chosen on a held-out validation set to land at roughly 1% FPR. That threshold is not a slider we eyeball — it is the output of a calibration step.
2. **"Hard evidence"** means we don't ask any one model to be a judge. Instead, we run a panel of small, single-purpose skills — Rspamd, header authentication, URL reputation, urgency, scam indicators, spam campaign matchers, and an error-pattern memory — and each one returns a typed, structured signal. The agent collects evidence before it forms a verdict.
3. **"Constrained LLM review only for ambiguous cases"** is the part that pushed us hardest. The LLM is not the classifier. The LLM is a final reviewer that activates only when the deterministic pipeline has flagged the case as ambiguous, and even then it cannot move a verdict freely — it has to satisfy explicit confidence and corroboration gates that we wrote in code, not in a prompt.

**Reasoning loop in plain English.** A raw email comes in. Rspamd scans it. The content model produces a calibrated malicious probability. Header-auth, URL reputation, urgency, scam indicator, spam campaign, and error-pattern memory each produce their own typed result. A decision policy reads all of this and assigns one of four labels — Normal, Spam, Phishing, or Suspicious. Only if the case sits in a gray zone does the LLM review layer activate, and even then it can only nudge the verdict if specific guardrail conditions are met. That is the loop: collect → classify deterministically → review only the ambiguous, under guardrails.

**Design priority** is the one line at the bottom: **minimize false positives while preserving recall.** Everything else — which model we ship, how the LLM is allowed to talk, when an upgrade is permitted — is downstream of that priority.

---

## Slide 2 — Literature Review Connection (LLM-PEA, Hasan et al., 2025)

**Speaker script (long form):**

Before we show the architecture, we want to spend a moment on the paper that shaped the whole guarded-review design, because it directly answers the question "why didn't you just let the LLM do it." That paper is **Hasan et al., "Phishing Email Detection Using Large Language Models," arXiv:2512.10104, 2025** — we refer to it as **LLM-PEA**.

Three findings from that paper drove our design:

1. **LLMs are promising but attackable.** The paper shows strong baseline detection rates for LLM phishing classifiers, but it also shows clear vulnerabilities under prompt-injection attacks, adversarial rewriting (paraphrasing the same scam to look more polite), and multilingual evasion. The lesson we took: a free-form LLM verdict is not a robust classifier — it can be talked out of its decision by the email itself.
2. **Evaluation has to be multi-vector.** Clean accuracy on a balanced test set is not enough. Phishing systems should be measured across attack type, prompt strategy, class imbalance, and source. That's why our benchmark is sourced from eight different corpora, and why we don't report a single accuracy number — we report F1, recall, FPR, runtime, and reviewer behavior side by side.
3. **Hardening is a deployment requirement, not a nice-to-have.** A real email-security agent has to have guardrails before it goes in front of users, especially given the asymmetry of false-positive cost we mentioned on the title slide.

So how does that show up in Email Guardian? Three places:

- **Evidence-first MCP tools.** Our skills — Rspamd, header auth, content model, URL reputation, urgency, scam, campaign, and memory — produce explicit, machine-readable signals. The LLM doesn't get to decide *first*; it sees the evidence already laid out.
- **Gray-zone LLM review only.** The LLM can refine ambiguous cases but cannot freely override the deterministic pipeline. If the deterministic stack says "Normal," the LLM does not get to upgrade it to "Phishing" unless specific structural conditions hold.
- **Guardrail rules encode the hardening.** Upgrades and downgrades require confidence, content-model support, and independent corroborating signals. We'll show you these rules explicitly on slide 6.

**The framing shift.** Instead of asking "Can an LLM detect phishing?", we asked: **"When is deterministic evidence enough, and when is hardened LLM review worth the risk and the cost?"** That second question is what our benchmark is set up to answer. We compare four reviewer models — Qwen3 local, GPT-5 Mini, GPT-5.4, and Claude Haiku 4.5 — on FPR, recall, runtime, reviewer acceptance, and a composite score that balances all of those.

---

## Slide 3 — Problem Framing

**Script:**

Three numbers anchor the project.

- **<1% target false-positive rate.** Wrongly flagging legitimate mail is the failure mode we treat as primary. That number is not a stretch goal — it's the operating point we calibrate the content model to.
- **High target recall.** We still need to catch malicious mail, but not by overreacting to weak signals. Recall has to come from real evidence, not from being trigger-happy.
- **Guarded final decision style.** Deterministic skills produce evidence; the LLM review layer is constrained and cannot freely overturn the pipeline.

The three rules at the bottom summarize the policy: **Avoid LLM-as-final-judge. Use calibrated detector plus evidence. Allow LLM review only in gray zones.**

---

## Slide 4 — System Architecture

**Script:**

This is the skill surface. The MCP layer turns email classification into evidence collection — every skill has one job, and the agentic loop decides which evidence is needed before it commits to a verdict.

A raw email goes in. The agent extracts headers, sender identity, links, body text, campaign patterns, and prior-error signals. It then routes through the skill library:

- **`rspamd_scan_email`** — calls the local Rspamd `/checkv2` HTTP endpoint. Rspamd is an industrial-grade open-source spam scanner: it runs Bayesian filters, header rules, URL reputation, RBL lookups, DMARC/SPF/DKIM checks. Our wrapper normalizes the raw JSON into a structured object with `risk_level`, `action`, `score`, `categories` (phishing / spoofing / suspicious_links / authentication_issue / reputation_issue / spam / content_anomaly / attachment_risk), and a ranked list of `symbols`. **Deterministic** for a given Rspamd configuration. We treat its score as a *signal*, not a verdict — Rspamd alone is too noisy on header artifacts and Bayes drift to be the final classifier.

- **`email_header_auth_check`** — parses the RFC822 header block. Pulls From, Reply-To, Return-Path, and Message-ID domains. Checks organizational-domain alignment across them. Parses the `Authentication-Results` header for SPF, DKIM, DMARC, and ARC outcomes. Flags brand-name impersonation (e.g., "PayPal" in From-name on a non-PayPal domain). **Fully deterministic** — pure parser plus regex. It is high precision on hard auth failures and low recall by itself, which is exactly what we want for this role.

- **`content_model_check`** — this is the calibrated primary gate. **TF-IDF word n-grams (1–2)** plus **TF-IDF character n-grams (3–5, char_wb)**, fed into a **Logistic Regression with class weight {ham: 2.0, spam: 1.0}**. The decision threshold is selected on the validation set so that test FPR lands at the project target. Reported metrics on the official split: **Test AUC 0.9991, Test FPR 0.99966%, Test recall 98.93%, Test precision 98.95%.** It is the strongest single skill in the stack and the reason the whole pipeline can hold a 1% FPR. **Deterministic** — same input, same probability, same threshold.

- **`url_reputation_check`** — extracts URLs from the body and computes structural features: number of URLs, presence of IP-literal URLs, max/avg URL length, max/avg subdomain depth, number of links, exclamation count, HTML-flag, attachment count. A **gradient-boosting classifier** trained on these features outputs a phishing probability. There is a deliberate **marketing-template dampener**: if the message has at least two marketing footers (Unsubscribe, View Online, Manage Preferences) and no account-security vocabulary, the score is capped to avoid flagging legitimate newsletters. **Deterministic ML.**

- **`urgency_check`** — TF-IDF vectorizer feeding a **multi-class logistic regression** (`not urgent / somewhat urgent / very urgent`). Returns an urgency probability and a risk contribution. Captures the "ACT NOW / VERIFY IMMEDIATELY / ACCOUNT SUSPENDED" register that legitimate transactional mail rarely uses. **Deterministic ML.** It is a *contributing* signal — never used alone for an upgrade.

- **`scam_indicator_check`** — high-precision deterministic regex/lexical rules over subject + From + Reply-To + readable body. Examples: PayPal lookalikes (paypai, paypa1), gift-card or crypto payment demands, extortion threats, free-mail Reply-To addresses claiming to be from official organizations, suspicious payment/recovery URLs (.tk, secure-verify, restore-account, pay=now), and the classic Microsoft/Windows-Defender lookalike patterns. **Pure rules, deterministic, designed for high precision** — when it fires, it is almost always something.

- **`spam_campaign_check`** — separate high-precision rule set for known *campaign* patterns: stock-pump emails ("aggressive buy", "target price"), pharmacy spam, replica-watch campaigns, payment-mule recruiting, pirated-software offers, and dataset-specific markers. **Deterministic.** Designed to improve spam recall *only after* the main scan is already suspicious — it is not allowed to fire as the sole upgrade reason.

- **`error_pattern_memory_check`** — a learned-from-mistakes lookup. We mined the dataset for patterns that previously caused misclassifications and stored them under `runtime/error_patterns/patterns.json`. Each incoming email is scored against stored templates by sender domain, normalized subject, subject keyword overlap, current verdict, and the risk levels of the other skills. **Deterministic scoring.** It only fires on strong matches (minimum score 7–8 depending on template kind), so it cannot drift the system on weak matches.

After the skills, the **decision policy** assigns one of four labels: **Normal, Spam, Phishing, Suspicious.** That label feeds the **reasoning loop** and, if the case is ambiguous, the **LLM review layer.**

---

## Slide 5 — Benchmark Design

**Script:**

We controlled the dataset and varied the reviewer. Four runs:

| Test | Reviewer model | Emails | Mode |
|---|---|---|---|
| Test 1 | Qwen3 Local | 10,000 | Balanced 50/50 |
| Test 2 | GPT-5 Mini | 10,000 | Balanced 50/50 |
| Test 3 | GPT-5.4 | 10,000 | Balanced 50/50 |
| Test 4 | Claude Haiku 4.5 | 10,000 | Balanced 50/50 |

Each run uses the same balanced 10,000-email subset, sourced across **eight corpora** — Enron, GitHub phishing, Meajor, Nazario, SpamAssassin, plus three additional sources. The deterministic pipeline (the seven skills above) is held constant. Gray-zone LLM review is active. Free-form LLM verdicts are disabled. So the only thing varying between runs is the reviewer backend, which means the differences we report are attributable to the reviewer — not to data leakage or pipeline drift.

---

## Slide 6 — LLM Review Layer

**Script:**

The LLM is a **constrained final layer**, not a replacement classifier. It activates only when the deterministic pipeline has produced an ambiguous case, and it operates in one of three modes:

- **`downgrade_fp` — the system has produced a positive verdict (Spam or Phishing) and we suspect it might be a false positive.** The LLM may downgrade only if it returns medium-or-higher confidence *and* there are at least four independent benign corroborating signals. Hard phishing cannot jump straight to Normal under any condition.
- **`refine_positive` — Spam vs. Phishing is ambiguous.** Upgrade Spam → Phishing requires high confidence, an account-security context, and at least three phish-corroborating signals. Downgrade requires medium-or-higher confidence and at least four benign corroborations.
- **`upgrade_fn` — Normal verdict, but we suspect a false negative.** This is the hardest gate by design. It requires **high** confidence, **content-model support** (`is_malicious=True` or near-threshold), **and at least two independent strong signals** (for example: scam indicator matched plus campaign matched, or content malicious plus suspicious URLs plus header risk). For Phishing specifically, it additionally requires account context and corroboration from header risk OR URL risk OR scam match.

The shaded box on the slide lists the explicit guardrails:

- FP downgrade needs medium confidence
- Hard phishing cannot jump straight to Normal
- FN upgrade needs high confidence
- FN upgrade needs content support
- FN upgrade needs two independent signals
- Positive refinement needs high phishing corroboration

These are not in the prompt. They are in our guardrail code (`_developer_apply_llm_review` in `desktop_pet.py`). The LLM can return any verdict it wants — if the verdict doesn't satisfy the guardrail conditions, we keep the deterministic decision. That is the heart of "constrained final reviewer."

---

## Slide 7 — UI: Model Section *(quick)*

The model controls have two dropdowns. **Provider** picks the backend (gemini, ollama, tokenrouter, puter-openai). **Model** picks the concrete model exposed by that provider — for example, on tokenrouter you get GPT-5 Mini, GPT-5.4, and Claude Haiku 4.5. Hit **Switch Model** to apply; the status bar updates.

---

## Slide 8 — UI: Mailbox Section *(quick)*

Once a mailbox is bound, this section lets you pick an account and page through scanned emails. **Refresh** reloads the saved mailbox list. **Show Latest 10** displays the newest analyzed messages. **Load 10 More** pages older results without clearing the view.

---

## Slide 9 — UI: Bind Mailbox Form *(quick)*

Standard IMAP form: email, optional username, app password (Gmail requires an app password, not the account password), IMAP host (defaults to `imap.gmail.com`), folder (`INBOX` by default). One-line security note: **credentials stay local — do not expose the MCP/IMAP server publicly without authentication.**

---

## Slide 10 — UI: Functions Section *(quick)*

Function buttons switch the workspace between input modes: **Chat View** (conversational), **Sample Email** (preloaded demo), **Email File / Headers File** (file picker), **Paste Email / Paste Headers** (manual paste), and the utility buttons **Reset / Help / Developer Mode / Quit**. Developer Mode is what launches the benchmark experiments behind the scenes.

---

## Slide 11 — *(image-only slide; transition into experiment results)*

This is a visual dashboard. We'll let it speak — the next two slides give the numbers.

---

## Slide 12 — Experiment Results: Quality and Runtime

**Script:**

The four models land in a narrow quality band, but they differ sharply on FPR and runtime. The headline read:

- **GPT-5.4** and **Qwen3 Local** have the strongest F1 balance.
- **Claude Haiku 4.5** has the **lowest false-positive rate** of the four (0.36%).
- **GPT-5 Mini** is the slowest and the only one whose composite drops sharply once we factor in runtime and reviewer behavior.

Reported numbers on the 10,000-email balanced benchmark:

| Reviewer | FPR | Runtime |
|---|---|---|
| Qwen3 Local | 0.72% | 62.3 min |
| GPT-5 Mini | 0.38% | 140.6 min |
| GPT-5.4 | 0.44% | 67.4 min |
| Claude Haiku 4.5 | 0.36% | 102.7 min |

All four sit at or below the 1% FPR target — that's the deterministic pipeline holding the line. The differences between them come from how often the reviewer accepts a downgrade, how often it triggers, and how long it takes per call.

---

## Slide 13 — Composite Ranking and Weight Logic

**Script:**

We don't pick a winner on a single metric — we use a composite score because no single metric captures the project goal. The composite ranking comes out as:

- **Test 3 — GPT-5.4 — 0.855** (winner)
- **Test 1 — Qwen3 Local — 0.680**
- **Test 4 — Claude Haiku 4.5 — 0.552**
- **Test 2 — GPT-5 Mini — 0.325**

**The composite formula** (this is the line on the slide):

```
composite = 0.28·F1 + 0.18·Recall + 0.18·(1−FPR) + 0.10·Accuracy
          + 0.08·Precision + 0.10·Runtime + 0.08·LLM_accepted
```

Each of those seven inputs is **min–max normalized across the four runs first**, so what we're combining are scores in [0,1] for each metric, where 1 is the best run on that metric and 0 is the worst. For FPR and runtime — where lower is better — we use the inverted normalization `(max − value) / (max − min)`. For everything else, higher is better.

**Why these specific weights?** They come from a **priority-to-weight normalization**:

```
weight_i = priority_i / Σ priority_j
```

We assigned each metric a priority score that reflects what the project actually optimizes:

| Metric | Priority | Final Weight | Why this number |
|---|---|---|---|
| F1 | 7 | 0.28 | Single best summary of the precision/recall tradeoff — our project headline |
| Recall | 4.5 | 0.18 | We must catch malicious mail; recall is the second axis |
| (1 − FPR) | 4.5 | 0.18 | Symmetric to recall — the project is explicitly conservative about FPs |
| Runtime | 2.5 | 0.10 | Real product cost — slow review = unusable in an inbox |
| Accuracy | 2.5 | 0.10 | Useful summary, but redundant with F1, so down-weighted |
| Precision | 2 | 0.08 | Captured implicitly through F1 and (1−FPR), kept for completeness |
| LLM accepted | 2 | 0.08 | Penalizes reviewers that *never* contribute and reviewers that drift; rewards the ones whose review actually moves cases |
| **Σ** | **25** | **1.00** | |

So the weight logic says: F1 is the main thing (28%), recall and FPR-control are tied for second (18% each), runtime is a real-product factor (10%), and accuracy/precision/reviewer-usefulness are small but non-zero contributors. This is why **GPT-5.4 wins** — it lands in the top quality band, has acceptable FPR, runs roughly twice as fast as GPT-5 Mini, and its review acceptance rate is healthy. And it is why **Claude Haiku 4.5**, despite having the *lowest* FPR, comes in third — its slower runtime and lower review-acceptance ratio cost it composite points. And it is why **GPT-5 Mini**, despite a low FPR, finishes last — it's roughly 2.3× slower than the leaders, which the runtime weight punishes hard.

The headline message of the score: **the composite is not the best on every metric — it is the best all-around tradeoff under our project priorities.**

---

## Slide 14 — *(closing image / Thank you)*

Wrap-up:

> Email Guardian treats email security as evidence collection, not LLM judgment. The calibrated content model holds the FPR line; high-precision rule skills add evidence; the LLM reviews only the gray zone, only under guardrails. On a 40,000-email benchmark, GPT-5.4 wins on the composite score (0.855); Claude Haiku 4.5 wins on raw FPR (0.36%); the architecture is the same across all four runs. Thanks — we're happy to take questions, then we'll run the live demo.

---

# Anticipated Audience Questions and Drafted Answers

### Q1. Why not just use the content model alone? It already hits ~1% FPR and ~99% recall on the test set.
**A.** Two reasons. First, source-stratified FPR can spike well above the global 1% on certain corpora — the content model is calibrated globally, so a single number hides per-source drift. Second, the rule skills (scam, campaign, header auth) catch attacks that the content model is by design weak on: novel impersonation, lookalike domains, account-recovery URLs. The content model is the primary gate; the rule skills are the safety net for the cases the content model can't see.

### Q2. If the LLM has guardrails this strict, why use an LLM at all?
**A.** Two genuine wins from the LLM layer: (1) **downgrading false positives** in routine business and marketing mail that the rule stack flagged on weak signals — this is the dominant LLM action in our runs, and (2) **separating Spam from Phishing** when the deterministic policy has labeled something as a generic positive. Both of those are bounded, low-risk movements. We deliberately turned off `allow_normal_upgrade` by default because that is the move that historically wrecks FPR.

### Q3. Why is the LLM not allowed to upgrade a Normal verdict in the default setting?
**A.** Because we measured it. With `allow_normal_upgrade=True`, even a small per-email upgrade rate on legitimate mail breaks the 1% FPR target on a balanced 10,000-email run — there are simply many more legitimate emails than positives, so a 0.5% LLM-driven flip rate adds 0.5 percentage points to FPR. The guarded version is enabled when `hard_upgrade_gate` is satisfied (content-model malicious or near-threshold + ≥2 strong signals + account context or campaign + Rspamd ≥ 8), but in the default benchmark we leave it off.

### Q4. Rspamd already gives a phishing score. Why not just use it as the verdict?
**A.** Rspamd is excellent as a *signal* but bad as a *verdict*. Its score is shaped by header artifacts, Bayes drift on the local corpus, missing-header noise, and (in our test environment) mock-server quirks. We saw Rspamd produce high scores on legitimate mail with merely sloppy headers. So we use Rspamd's symbols and categories as evidence, not its score as the decision.

### Q5. The composite weights — aren't you just picking weights that make GPT-5.4 win?
**A.** Fair challenge. The weights were set *before* we ran the four-model benchmark, from project priorities (F1 first, then recall and FPR-control, then runtime, then accuracy/precision/reviewer-usefulness). If you set every priority to 1, GPT-5.4 still wins; if you double the FPR weight, Claude Haiku 4.5 catches up but doesn't pass. The ordering is not weight-fragile.

### Q6. You used a *balanced* 50/50 benchmark. Real inboxes are not 50/50 — most mail is legitimate.
**A.** Correct, and that's why we report FPR explicitly rather than only accuracy. FPR is a per-class rate that is invariant to class balance, so a 1% FPR on a balanced set is a 1% FPR on a 99/1 set. The reason for balanced sampling was statistical: with 10,000 emails, balancing gives us 5,000 positives — enough to estimate recall tightly. On an inbox-realistic distribution, you would see far fewer phishing emails per evaluation but the per-class rates we report carry over.

### Q7. How do you handle prompt-injection attacks against your LLM reviewer? The Hasan paper specifically calls those out.
**A.** Three layers of defense. (1) The LLM never sees the email body without already having the deterministic verdict and the structured signal summary in context. (2) The LLM's verdict is parsed out of strict JSON and rejected if the format isn't right. (3) Even a perfectly-injected verdict has to pass the guardrail in `_developer_apply_llm_review` — confidence threshold, corroboration counts, allowed transitions. An injection that says "PHISHING, high confidence" still cannot upgrade a Normal verdict if `strong_positive_support < 2` or content-model support is absent.

### Q8. The error-pattern memory — isn't that just a way to overfit to the benchmark?
**A.** It's a risk we manage. The patterns are mined from *training-side* misclassifications, scored against new emails by sender domain, normalized subject, keyword overlap, current verdict, and risk levels — not by raw text matching. The minimum match score (7–8 depending on template kind) is set high enough that weak similarities don't trigger. We verified there is no leakage from the test set into the pattern store.

### Q9. Why Claude Haiku 4.5 specifically — why not Sonnet or Opus?
**A.** Cost and latency. The reviewer is invoked many times per benchmark run (once per gray-zone email), and the per-call value of a larger model is small once the deterministic pipeline has already done the heavy lifting. Haiku 4.5 was the right point on the cost/latency curve for a *constrained reviewer* role. If we were using the LLM as the primary classifier, the choice would be different — but we explicitly aren't.

### Q10. What happens when Rspamd is unreachable?
**A.** The `rspamd_scan_email` skill returns a typed error (`connection_error`) and the rest of the pipeline continues without that signal. The content model is the primary gate, so the system stays useful. The decision policy treats missing Rspamd evidence as missing — it does not assume "low risk."

### Q11. Can the user override a verdict? Does the system learn from corrections?
**A.** Yes. The runtime SQLite database has a `decision_memory` table that stores user corrections (sender domain, normalized subject, keywords, prior verdict, corrected verdict). The IMAP pipeline applies that memory before returning a verdict on future similar emails. We didn't run a benchmark with active correction memory because that conflates pipeline quality with adaptive personalization — we wanted the four-model comparison to be apples-to-apples.

### Q12. What's the smallest deployment unit — can someone self-host this?
**A.** Yes. The whole stack is local: Rspamd is a local service on `127.0.0.1:11333`; the content/URL/urgency models are pickled scikit-learn classifiers in the repo; the rule skills are pure Python; the MCP server runs over stdio. The only thing that hits the network is the LLM reviewer, and even that can be Qwen3 via a local Ollama — that's our Test 1 configuration, and it scored second on the composite.

### Q13. What's your biggest known weakness?
**A.** Source shift. The content model is calibrated on our prepared dataset; real production traffic from a new tenant will sit at a different operating point until the threshold is recalibrated. Our recommended deployment path is to gather a few hundred labeled samples from the new tenant, recalibrate the threshold to hit local 1% FPR, and only then turn the LLM reviewer on.

### Q14. How long does a single email take end-to-end?
**A.** Without LLM review: roughly tens of milliseconds — Rspamd plus seven local skills. With LLM review (only on gray-zone cases): adds the per-call latency of the chosen reviewer. On the 10,000-email runs, that ranged from ~62 minutes (Qwen3 local) to ~141 minutes (GPT-5 Mini), so the per-email amortized cost is roughly 0.4–0.85 seconds depending on reviewer. The deterministic pipeline alone is fast enough to run inline on inbox delivery.

### Q15. What would change your design if you were doing this again?
**A.** Two things. (1) Source-stratified calibration from day one — fitting one global threshold hides per-corpus drift, and we'd build that in upfront. (2) A second deterministic gate trained specifically on the *false positives* the first model produces — a "second opinion" calibrator — before the LLM ever gets called. That would let us shrink the gray zone and keep more decisions out of the reviewer entirely.
