# Presentation Script: Agentic vs. Baseline Email Security Pipeline
### Spoken script — 5 slides (~9 minutes)

---

## Slide 1 — The Problem and the Two Approaches

**Spoken script:**

Email threats are not uniform. An obvious phishing attempt and a sophisticated spear-phishing attack look completely different — and a system that treats them the same way will either waste resources or miss the subtle ones.

More importantly, in this system, a false positive is the disaster. Flagging a legitimate business email as phishing means it gets buried, blocked, or buried in a warning queue. The user misses something important. That is the failure mode we are most concerned about.

We built two pipelines to test this directly.

The **baseline** is exhaustive: every email is run through all four security skills unconditionally — rspamd content scanning, header authentication checking, an urgency classifier, and a URL reputation scorer. All four fire every time. It takes the outputs, combines them with fixed logic, and returns a verdict. No reasoning. No adaptation. Fast and deterministic.

The **agentic pipeline** uses Gemini 2.5 Flash as the decision-maker. Gemini reads the email, picks a skill, observes the result, and decides: is this enough to commit, or do I need more evidence? It chains tools only when the signal is genuinely ambiguous.

The research question is: does adaptive skill selection produce better verdicts? And what does it cost?

---

## Slide 2 — The Skill Library

**Spoken script:**

Before the results, a quick look at what each skill actually does — because the comparison only makes sense if you understand what each one contributes.

`rspamd_scan_email` is the first-pass scanner. It submits the raw email to rspamd's `/checkv2` endpoint and returns a score against a required threshold, categorised signals like phishing indicators, SPF failures, and Bayesian spam scores, and a normalised risk level. It is fast and broad.

`email_header_auth_check` is purely structural. It parses SPF, DKIM, DMARC, and ARC results from the headers, checks for domain mismatches across From, Reply-To, and Return-Path, and returns findings with severity levels. It doesn't read the body at all.

`urgency_check` is trained. It runs a logistic regression — trained on 355,000 labelled emails — against TF-IDF features from the subject and body, and returns a continuous urgency score between zero and one. The model was trained to optimise specificity: it almost never flags a legitimate email as urgent. When it does fire, you can trust it.

`url_reputation_check` is also trained — a gradient boosting classifier on pre-engineered URL features: count, length, subdomain depth, whether any URL uses a raw IP address. Same dataset, same specificity-first tuning. Low false positive rate by design.

Together these four cover four orthogonal dimensions: content toxicity, sender authentication, psychological pressure, and link structure.

---

## Slide 3 — Results: Verdict Quality

**Spoken script:**

We tested four emails chosen to stress-test the comparison: an obvious phishing attempt, a legitimate university IT notice, an ambiguous marketing email, and a targeted spear-phishing attack.

**Obvious phishing.** Both systems agreed: phishing, high confidence. The agent called only rspamd — scored 14.7 out of 15.0 — and stopped. No need to go further. The baseline ran all four skills, two of which added nothing new.

**Legitimate email.** This is the key result. The baseline returned phishing — a false positive. Because its verdict logic trusts rspamd's output directly, and rspamd flagged it, the baseline got it wrong. The agent called rspamd, saw the contradiction with the header authentication check — SPF pass, DKIM pass, DMARC pass for columbia.edu — and reasoned that the rspamd result was inconsistent with the authenticated evidence. It correctly returned benign. The agent avoided the exact failure mode we care most about.

**Ambiguous marketing.** Here the agent called all four tools before committing. rspamd flagged high risk; header auth showed a domain mismatch but DMARC passed; urgency_check returned a score of 1.0 — maximum urgency; URL reputation came back low risk. Four conflicting signals. The agent returned "suspicious, moderate confidence" — not a definitive phishing verdict — which is the correct answer when the evidence genuinely conflicts. The baseline called it phishing regardless.

**Spear phishing.** Both systems agreed: phishing. But the baseline now has a much richer evidence trail — the urgency classifier returned "somewhat urgent" with a score of 0.60, corroborating the triple authentication failure. That corroboration is what the new skills add to the baseline: independent confirmation from a completely different signal source.

**The pattern:** the agent produces zero false positives, correctly grades uncertainty on the ambiguous case, and skips unnecessary skill calls on clear-cut cases.

---

## Slide 4 — Results: Cost and Efficiency

**Spoken script:**

The agent's better verdicts come at a cost. Here are the numbers.

On **latency**, the baseline ran in 49 to 1,881 milliseconds. The 1,881-millisecond outlier on the obvious phishing case is because the urgency model was being loaded into memory for the first time — subsequent runs are 50 milliseconds. The agent took 8 to 64 seconds, driven entirely by Gemini API round trips.

On **tool calls**, the agent adapted exactly as expected. For the obvious phishing case — score 14.7 out of 15.0, clear signal — one tool call and done. For the legitimate and spear-phishing emails — two tool calls each. For the ambiguous case — all four. The agent allocated reasoning effort proportional to how hard the email was to classify.

On **token usage**, the ambiguous email was the most expensive at roughly 15,000 tokens total. The obvious phishing case cost only 7,500 — Gemini made its decision quickly and cheaply.

The pattern is consistent: the agent spends more tokens and time exactly where the evidence is ambiguous. It is not uniformly expensive.

| Email | Baseline ms | Agent ms | Agent tool calls | Agent tokens |
|---|---|---|---|---|
| Obvious phishing | ~50 | 8,476 | 1 | 7,528 |
| Legitimate | 51 | 16,015 | 2 | 13,008 |
| Ambiguous marketing | 49 | 64,183 | 4 | ~15,200 |
| Spear phishing | 49 | 14,483 | 2 | 9,254 |

---

## Slide 5 — What This Means and What Comes Next

**Spoken script:**

The comparison surfaces a clear architectural insight.

The baseline is fast, cheap, and thorough — but it cannot reason. When two skills return contradictory signals, the baseline picks a winner by rule. That is why it produced a false positive on the legitimate email: rspamd said phishing, the rule followed rspamd, done. The header auth result that said the opposite was outweighed silently.

The agent treats skill outputs as evidence rather than verdicts. It can say: these two signals conflict, one of them is more credible in this context, here is my reasoning. That is why it correctly overrode the false positive — and why it held back from a definitive verdict on the ambiguous case rather than committing to a wrong answer.

The new ML skills — urgency and URL reputation — add something specific: **independent, quantified signals from orthogonal dimensions**. The urgency classifier caught that the Shopify email was maximally urgent, which pushed the agent to call more tools rather than stopping early. The URL reputation classifier corroborated the authentication failure on the spear-phishing case. Neither of these were available to the original two-skill system.

What comes next is adding a semantic reasoning skill — an LLM phishing reasoner that reads the full email and provides a structured confidence score. With that in place, the agent's skill selection becomes the central research contribution: can it learn when to invoke the expensive LLM reasoner versus when the cheaper trained classifiers are sufficient? And does the baseline — running all four skills exhaustively — serve as the ground truth benchmark against which the agent's adaptive efficiency is measured?

That is the experiment.

---

*End of script. Estimated speaking time: ~9 minutes.*
