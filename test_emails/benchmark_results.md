# Email Security Benchmark Results

**Baseline:** exhaustive — all 4 skills run on every email
**Agent:** Gemini 2.5 Flash — adaptive skill selection via MCP
**Skills available:** `rspamd_scan_email`, `email_header_auth_check`, `urgency_check`, `url_reputation_check`

> Note: Email 4 agent result carried from prior run (quota limit reached). Baseline for all 4 emails is fresh.

---

## Summary Table

| # | Email | Baseline Verdict | Urgency (score) | URL Risk (score) | Agent Tools Called | Agent Verdict | Baseline ms | Agent ms | Tokens In | Tokens Out |
|---|-------|-----------------|-----------------|------------------|--------------------|---------------|-------------|----------|-----------|------------|
| 1 | Obvious Phishing (QuickBooks) | phishing_or_spoofing | not urgent (0.00) | low (0.034) | rspamd_scan_email | **Phishing (High Confidence)** | 1881 | 8476 | 5156 | 2372 |
| 2 | Legitimate (Columbia IT) | phishing_or_spoofing | not urgent (0.00) | low (0.002) | rspamd_scan_email, email_header_auth_check | Benign with high confidence | 51 | 16015 | 10010 | 2998 |
| 3 | Ambiguous (Shopify marketing) | phishing_or_spoofing | very urgent (1.00) | low (0.021) | rspamd_scan_email, email_header_auth_check, url_reputation_check, urgency_check | **Suspicious** — moderate confidence | 49 | 64183 | ~12000 | ~3200 |
| 4 | Spear Phishing (Columbia IT alert) | phishing_or_spoofing | somewhat urgent (0.60) | low (0.008) | rspamd_scan_email, email_header_auth_check | **Phishing** — high confidence | 49 | 14483 | 6947 | 2307 |

---

## Per-Email Detail

### 1. Obvious Phishing (QuickBooks impersonation)
**File:** `01_obvious_phishing.eml`

#### Baseline (all 4 skills)
- **Final verdict:** phishing_or_spoofing
- **rspamd:** score=14.7 / 15.0  risk=high  categories=authentication_issue, phishing, sender_profile, spam, suspicious_links
- **header_auth:** risk=medium  findings=domain_mismatch
- **urgency_check:** label=not urgent  score=0.000  contribution=low
- **url_reputation:** phishing_score=0.034  suspicious=False  risk=low
- **Time:** 1881 ms  (4 skills, no LLM)

#### Agent (Gemini 2.5 Flash)
- **Tools called:** rspamd_scan_email (1 call)
- **Time:** 8476 ms
- **Tokens:** 5156 in / 2372 out
- **Verdict:** Phishing (High Confidence). rspamd score 14.7/15.0 with PHISHING symbol (+5.0), SPF_FAIL (+3.0), BAYES_SPAM (+4.5). Sender domain automated-mailsender.com does not match claimed Intuit identity. Do not click links.

---

### 2. Legitimate (Columbia IT maintenance notice)
**File:** `02_legitimate.eml`

#### Baseline (all 4 skills)
- **Final verdict:** phishing_or_spoofing  ← **FALSE POSITIVE**
- **rspamd:** score=14.7 / 15.0  risk=high  categories=authentication_issue, phishing, spam (mock server artefact)
- **header_auth:** risk=low  findings=dmarc_pass
- **urgency_check:** label=not urgent  score=0.000  contribution=low
- **url_reputation:** phishing_score=0.002  suspicious=False  risk=low
- **Time:** 51 ms  (4 skills, no LLM)

#### Agent (Gemini 2.5 Flash)
- **Tools called:** rspamd_scan_email, email_header_auth_check (2 calls)
- **Time:** 16015 ms
- **Tokens:** 10010 in / 2998 out
- **Verdict:** Benign with high confidence. email_header_auth_check confirmed SPF pass, DKIM pass, DMARC pass for columbia.edu. Agent reasoned that rspamd result contradicts the authenticated headers and correctly overrode it. No action required.

---

### 3. Ambiguous (Shopify flash-sale marketing)
**File:** `03_ambiguous_marketing.eml`

#### Baseline (all 4 skills)
- **Final verdict:** phishing_or_spoofing
- **rspamd:** score=14.7 / 15.0  risk=high  categories=authentication_issue, phishing, spam
- **header_auth:** risk=medium  findings=domain_mismatch, dmarc_pass
- **urgency_check:** label=very urgent  score=1.000  contribution=high  ← **strong signal**
- **url_reputation:** phishing_score=0.021  suspicious=False  risk=low
- **Time:** 49 ms  (4 skills, no LLM)

#### Agent (Gemini 2.5 Flash)
- **Tools called:** rspamd_scan_email, email_header_auth_check, url_reputation_check, urgency_check (4 calls — ALL skills)
- **Time:** 64183 ms
- **Tokens:** ~12000 in / ~3200 out
- **Verdict:** Suspicious — moderate confidence. Agent exhausted all tools before committing. rspamd flagged high risk; header auth showed domain mismatch but DMARC pass; urgency_check returned very urgent (score=1.0); url_reputation low. Conflicting signals led to "suspicious" rather than definitive phishing verdict — correct call given genuine ambiguity.

---

### 4. Spear Phishing (Columbia IT security alert)
**File:** `04_spear_phishing.eml`

#### Baseline (all 4 skills)
- **Final verdict:** phishing_or_spoofing
- **rspamd:** score=14.7 / 15.0  risk=high  categories=authentication_issue, phishing, spam
- **header_auth:** risk=high  findings=dmarc_fail, spf_not_pass, dkim_not_pass
- **urgency_check:** label=somewhat urgent  score=0.600  contribution=medium  ← **corroborating signal**
- **url_reputation:** phishing_score=0.008  suspicious=False  risk=low
- **Time:** 49 ms  (4 skills, no LLM)

#### Agent (Gemini 2.5 Flash)
- **Tools called:** rspamd_scan_email, email_header_auth_check (2 calls)
- **Time:** 14483 ms
- **Tokens:** 6947 in / 2307 out
- **Verdict:** Phishing — high confidence. DKIM fail + SPF softfail + DMARC fail combined with domain impersonation (columbia-university.net vs columbia.edu) and urgency language ("ACTION REQUIRED", "suspended within 24 hours"). Do not click links, report immediately.

---

## Comparison Charts

### Latency (ms)

| Email | Baseline (4 skills) | Agent |
|-------|---------------------|-------|
| Obvious Phishing | 1881 | 8,476 |
| Legitimate | 51 | 16,015 |
| Ambiguous marketing | 49 | 64,183 |
| Spear Phishing | 49 | 14,483 |

### Skill Calls per Email

| Email | Baseline | Agent (adaptive) | Skills Agent skipped |
|-------|----------|-----------------|----------------------|
| Obvious Phishing | 4 | 1 (rspamd only) | email_header_auth_check, urgency_check, url_reputation_check |
| Legitimate | 4 | 2 (rspamd, header_auth) | urgency_check, url_reputation_check |
| Ambiguous marketing | 4 | 4 (all) | — |
| Spear Phishing | 4 | 2 (rspamd, header_auth) | urgency_check, url_reputation_check |

### Baseline: ML Skill Signals

| Email | Urgency Label | Urgency Score | URL Phishing Score | URL Suspicious |
|-------|--------------|---------------|--------------------|----------------|
| Obvious Phishing | not urgent | 0.000 | 0.034 | False |
| Legitimate | not urgent | 0.000 | 0.002 | False |
| Ambiguous marketing | very urgent | 1.000 | 0.021 | False |
| Spear Phishing | somewhat urgent | 0.600 | 0.008 | False |

### Token Usage (Agent only)

| Email | Tokens In | Tokens Out | Total |
|-------|-----------|------------|-------|
| Obvious Phishing | 5,156 | 2,372 | 7,528 |
| Legitimate | 10,010 | 2,998 | 13,008 |
| Ambiguous marketing | ~12,000 | ~3,200 | ~15,200 |
| Spear Phishing | 6,947 | 2,307 | 9,254 |
