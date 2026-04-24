# Email Agent Project Context For Pro Model

## Goal

This project is an email security agent. The target operating point is extremely conservative:

- False positive rate around 1%.
- Recall around 90% or higher.
- In product terms, wrongly flagging legitimate mail is the main failure to avoid.

The central difficulty is that the deterministic low-FPR content model can reach the desired FPR/recall range on the prepared benchmark, but once an LLM is allowed to participate in final decision-making, it tends to over-interpret weak suspicious clues and increase false positives. The desired design is not "LLM decides phishing"; it should be "deterministic calibrated detector decides, LLM explains or reviews only under strict guardrails."

## Current System

The repository is `email_agent`. It includes:

- Desktop UI: `desktop_pet.py`
- Terminal/chat entrypoint: `chatbot.py`
- MCP server: `mcp_server.py`
- LangGraph agent runtime: `harness/runtime.py`
- Rule/UI verdict rendering: `harness/ui.py`
- Security skills under `skills/`
- Dataset preparation/evaluation under `dataset/`
- Runtime IMAP database under `runtime/imap_monitor/`
- Error-pattern memory under `runtime/error_patterns/patterns.json`

Providers supported:

- Gemini, default model usually `gemini-2.5-flash`
- Ollama/Qwen3 local mode
- Puter OpenAI bridge, default model `gpt-5.4`

Important caveat: Puter frontend bridge is normal chat only and is not an MCP client. Real local tool calls happen through the local LangGraph/MCP path.

## Data And Databases

There is no main SQL training database. The benchmark data is CSV-based.

Training/evaluation data:

- `dataset/raw/Nazario_5.csv`
- `dataset/raw/email_text.csv` from SpamAssassin-like data
- `dataset/raw/enron_data_fraud_labeled.csv`
- `dataset/raw/github_phishing_emails.json`
- `dataset/raw/meajor.csv`
- processed outputs in `dataset/processed/`

Prepared dataset summary:

- Full normalized rows: 615,910
- Binary training rows: 613,582
- Binary ham/legitimate: 531,935
- Binary spam/phishing positive: 81,647
- Enron fraud positives are excluded from binary training because they are not classic inbox spam/phishing.

Per-source counts:

- Enron: 445,090 legitimate, 2,327 fraud_internal excluded from binary training
- GitHub: 1,125 phishing, 1,000 spam, 950 legitimate
- Meajor: 60,650 legitimate, 48,034 spam, 1 unknown
- Nazario: 1,565 phishing, 1,500 legitimate
- SpamAssassin: 29,923 spam, 23,745 legitimate

Processed files:

- `dataset/processed/normalized_dataset.csv`
- `dataset/processed/spam_binary_dataset.csv`
- `dataset/processed/spam_binary_train.csv`
- `dataset/processed/spam_binary_val.csv`
- `dataset/processed/spam_binary_test.csv`
- JSONL evaluation outputs such as `skill_eval_results.*.jsonl`

Runtime SQLite database:

- Path: `runtime/imap_monitor/monitor.db`
- Tables:
  - `mailboxes`: bound IMAP accounts. Contains email address, username, app password, host, port, folder, polling interval, enabled flag, last UID, last poll, last error.
  - `email_results`: one row per analyzed IMAP message. Contains mailbox, UID, message id, subject, sender, analyzed time, Rspamd risk/score, header risk, final verdict, summary, memory hint, raw email path.
  - `decision_memory`: user correction memory. Stores sender domain, normalized subject, keywords, prior verdict, corrected verdict, notes, reference count.
- Current observed counts:
  - `mailboxes`: 1
  - `email_results`: 1,289
  - `decision_memory`: 0

Raw monitored emails are stored as `.eml` files under:

- `runtime/imap_monitor/messages/<mailbox>/UID.eml`

Error-pattern memory:

- Path: `runtime/error_patterns/patterns.json`
- Used by `skills/error_patterns/skill.py`
- It stores dataset-derived misclassification templates. Matching uses sender domain, normalized subject, subject keywords, current verdict, and risk signals.

## Models

There are two model paths with different quality.

Old low-FPR baseline:

- Code: `dataset/train_low_fpr_baseline.py`
- Model: `dataset/models/low_fpr_baseline.joblib`
- Features: hashed word/bigram text plus structured fields.
- Target FPR: 1%.
- Result in `dataset/reports/low_fpr_baseline_report.md`:
  - Test FPR around 1.07%
  - Test recall only about 0.9%
- This model hits low FPR only by destroying recall, so it is not the model to trust.

Current content model:

- Code: `skills/content_model/train.py`
- Model files:
  - `skills/content_model/model/word_vectorizer.pkl`
  - `skills/content_model/model/char_vectorizer.pkl`
  - `skills/content_model/model/classifier.pkl`
  - `skills/content_model/model/meta.pkl`
- Algorithm:
  - TF-IDF word ngrams 1-2
  - TF-IDF char_wb ngrams 3-5
  - LogisticRegression with class weight `{0: 2.0, 1: 1.0}`
  - Threshold chosen on validation set to satisfy target FPR
- Report: `dataset/reports/content_model_metrics.json`
- Current metrics:
  - Target FPR: 0.01
  - Threshold: 0.45840277448217515
  - Validation AUC: 0.999376
  - Test AUC: 0.999137
  - Test FPR: 0.0099965
  - Test recall: 0.989258
  - Test precision: 0.989499
- This already exceeds the requested recall target on the benchmark while staying around 1% FPR.

## Skills

Core skills:

- `rspamd_scan_email`: calls local Rspamd `/checkv2`, normalizes score, action, symbols, categories.
- `email_header_auth_check`: checks SPF/DKIM/DMARC/header authentication signals.
- `content_model_check`: calibrated text classifier intended to preserve low FPR.
- `url_reputation_check`: heuristic/model URL phishing score.
- `urgency_check`: urgency language detector.
- `scam_indicator_check`: high-precision phishing/scam patterns.
- `spam_campaign_check`: high-precision spam campaign patterns.
- `error_pattern_memory_check`: dataset-derived misclassification correction patterns.
- IMAP monitor skills: bind mailbox, poll mailbox, scan recent emails, list results, record corrections.

Rspamd is useful as a scanner but should not be the final classifier. It can produce high scores from header artifacts, Bayes symbols, missing headers, or mock-server artifacts. The code already has several guards for header-format noise and benign corroboration.

## Decision Flow

There are two important decision paths.

1. IMAP/tool pipeline in `skills/imap_monitor/skill.py`

- Scans raw RFC822 email with Rspamd.
- Runs header auth, urgency, URL reputation, scam indicators, spam campaign checks.
- Calls `_compose_final_verdict`.
- Applies error pattern guidance.
- Applies user decision memory.
- Stores result in SQLite.

Verdicts here are:

- `benign`
- `suspicious`
- `phishing_or_spoofing`
- `error`

2. Developer benchmark pipeline in `desktop_pet.py`

- Builds synthetic raw email from CSV row.
- Always runs Rspamd first.
- Routes follow-up skills with `_developer_routed_skills`.
- Runs content model whenever email text exists.
- Uses `_required_decision_label` from `harness/ui.py` to map signals to:
  - `Normal`
  - `Spam`
  - `Phishing`
- Then applies an especially important override:
  - If content model exists and `is_malicious` is false, decision becomes `Normal` unless already `Phishing`.
  - If content model exists and `is_malicious` is true, decision becomes `Spam` unless already `Phishing`.

This means the current benchmark path is intentionally anchored on the calibrated content model, which explains why it can hold FPR low.

## LLM Involvement

The LLM is used in two ways:

1. Main chat/LangGraph agent:

- User asks natural language questions.
- Agent can call MCP tools.
- Final answer is generated by the LLM.
- `harness/ui.py` can post-process tool payloads into a strict verdict format.

2. Developer final review path:

- `desktop_pet.py` has `_developer_build_llm_review_prompt`.
- The prompt tells the LLM to minimize false positives and preserve deterministic verdicts unless there is strong corroborated evidence.
- It returns JSON with `verdict`, `confidence`, `reason`.
- However, in the current `DeveloperExperimentWorker.run`, `_developer_predict_row(... llm_review_enabled=False ...)` hard-disables LLM review. This likely happened because enabling LLM review increased FPR.

The likely failure mode when LLM review is enabled:

- The deterministic model says `Normal`.
- The row is routed to gray-zone review due to weak conflicts such as Rspamd high score, urgency language, marketing words, account/security vocabulary, or content near threshold.
- LLM overweights natural-language suspiciousness and upgrades to `Spam` or `Phishing`.
- Even if each upgrade sounds plausible, at scale a small upgrade rate on legitimate mail breaks the 1% FPR target.

## Current Experimental Results

Recent developer run metrics show the no-LLM benchmark path often has high recall but FPR near or above target depending on source/sample:

- 20260422-025815-test1: 5,000 rows, FPR 1.04%, recall 99.57%, precision 99.18%.
- 20260422-032845-test1: 3,000 rows, FPR 1.12%, recall 99.64%.
- 20260422-071527-test1: 100 rows, FPR 2.00%, recall 98.00%.
- Some source-specific runs show much worse FPR, e.g. around 6.4%-7.35%, meaning source/domain shift matters.

Important: `content_model_metrics.json` shows the standalone content model can hit ~1% FPR and ~98.9% recall on the official split. The integration layer can still degrade this through Rspamd/rule/LLM overrides.

## Main Problem To Solve

Need a robust architecture that preserves low FPR even when LLM is present.

The Pro model should focus on:

1. Make the calibrated content model the primary binary gate.
2. Treat LLM as explanation/review, not as an unconstrained classifier.
3. Allow LLM upgrades from `Normal` to `Spam/Phishing` only under mathematically strict conditions.
4. Measure LLM-caused deltas separately:
   - deterministic prediction
   - LLM proposed verdict
   - final accepted verdict
   - whether LLM changed ham to positive
5. Add a gate like:
   - LLM may downgrade positive to Normal when deterministic evidence is weak.
   - LLM may split positive into Spam vs Phishing.
   - LLM may not convert Normal to positive unless content score is above threshold or multiple high-precision detectors agree.
6. Avoid using Rspamd high score alone as an upgrade reason.
7. Calibrate on source-stratified validation, because global FPR hides source-specific FPR spikes.

## Concrete Design Direction

Recommended final decision policy:

- Stage 1: deterministic content model produces calibrated `p_malicious`.
- Stage 2: choose binary decision using threshold selected for target FPR.
- Stage 3: high-precision rules can only upgrade when they have strong independent corroboration.
- Stage 4: LLM can only:
  - write user-facing explanation,
  - classify positive as Spam vs Phishing,
  - recommend "needs review",
  - or downgrade borderline positives.
- Stage 5: LLM cannot override a deterministic `Normal` to positive unless a hard allowlist of upgrade conditions is met.

Suggested upgrade allowlist:

- content model is malicious or very close to threshold and
- at least two independent high-precision signals are present:
  - URL high risk or suspicious URL
  - scam indicator matched
  - header auth high risk with explicit auth failure
  - Rspamd phishing/spoofing category, not just generic spam/Bayes/header noise
  - credential/payment/account-action pattern

If those conditions are absent, final binary must stay `Normal` even if the LLM says "suspicious".

## Key Files To Inspect

- `skills/content_model/train.py`: trains current good low-FPR content model.
- `skills/content_model/skill.py`: loads model and returns malicious score, threshold, risk level.
- `harness/ui.py`: `_required_decision_label`, current deterministic verdict logic.
- `desktop_pet.py`: `_developer_predict_row`, `_developer_gray_zone_reasons`, `_developer_build_llm_review_prompt`, developer benchmark UI.
- `skills/imap_monitor/skill.py`: IMAP production-like decision flow.
- `skills/imap_monitor/storage.py`: SQLite schema.
- `dataset/prepare_coms6901_dataset.py`: dataset normalization.
- `dataset/evaluate_dataset_with_skills.py`: batch evaluation with all skills.
- `dataset/reports/content_model_metrics.json`: best current model metrics.
- `dataset/reports/developer_runs/*/metrics.json`: integration benchmark history.

## Important Warning

Do not optimize only for apparent accuracy or recall. With 531,935 legitimate examples and 81,647 positives, even a small percentage of ham upgrades by the LLM creates unacceptable false positives. The core success criterion is source-stratified FPR near 1% with recall around or above 90%, not a persuasive LLM explanation.

