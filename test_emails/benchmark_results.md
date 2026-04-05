# Email Security Benchmark Results

**Baseline:** exhaustive — all 4 skills run on every email  
**Agent:** llama-3.1-8b-instant via Groq — adaptive skill selection via MCP  
**Skills available:** `rspamd_scan_email`, `email_header_auth_check`, `urgency_check`, `url_reputation_check`

---

## Summary Table

| # | Email | Baseline Verdict | Baseline Urgency | Baseline URL Risk | Agent Tools Called | Agent Verdict | Baseline ms | Agent ms | Tokens In | Tokens Out |
|---|-------|-----------------|-----------------|------------------|--------------------|---------------|-------------|----------|-----------|------------|
| 1 | Obvious Phishing (QuickBooks impersonation) | benign | not urgent (0.14) | low (0.07) | rspamd_scan_email, email_header_auth_check, url_reputation_check, urgency_check | Verdict: **Phishing (High Confidence)** | 3507 | 25251 | 18444 | 3476 |
| 2 | Legitimate (Columbia IT maintenance notice) | benign | not urgent (0.17) | low (0.01) | rspamd_scan_email, email_header_auth_check | Verdict: Benign (High Confidence) | 66 | 46050 | 8900 | 1985 |
| 3 | Ambiguous (Shopify flash-sale marketing) | benign | very urgent (0.93) | low (0.12) | rspamd_scan_email, urgency_check, url_reputation_check | Verdict: Benign (Moderate Confidence) | 54 | 19788 | 13400 | 2936 |
| 4 | Spear Phishing (Columbia IT security alert) | suspicious | somewhat urgent (0.98) | low (0.08) | rspamd_scan_email, email_header_auth_check, urgency_check, url_reputation_check | **Verdict: Phishing (High Confidence)** | 44 | 56258 | 15416 | 3532 |

---

## Per-Email Detail

### 1. Obvious Phishing (QuickBooks impersonation)
**File:** `01_obvious_phishing.eml`

#### Baseline (all 4 skills)
- **Final verdict:** benign
- **rspamd:** score=None / None  risk=None  categories=none
- **header_auth:** risk=medium  findings=domain_mismatch
- **urgency_check:** label=not urgent  score=0.1389  contribution=low
- **url_reputation:** phishing_score=0.0698  suspicious=False  risk=low
- **Time:** 3507 ms  (4 skills, no LLM)

#### Agent (Gemini 2.5 Flash)
- **Tools called:** rspamd_scan_email, email_header_auth_check, url_reputation_check, urgency_check (4 call(s))
- **Time:** 25251 ms
- **Tokens:** 18444 in / 3476 out
- **Verdict:**

  Verdict: **Phishing (High Confidence)**
  
  **Tool Evidence:**
  *   **Email Header Authentication Check:**
      *   Risk Level: Medium.
      *   SPF and DKIM passed for `automated-mailsender.com`.
      *   **Finding:** A significant domain mismatch was detected. The `From` header displays "Intuit <qbo@automated-mailsender.com>", while the `Return-Path` is `<bounces+13945262-824e-jw4822=columbia.edu@em8939.automated-mailsender.com>`. The email purports to be from "Intuit" but originates from a generic "automated-mailsender.com" domain, indicating impersonation.
  *   **URL Reputation Check:**
      *   Phishing Score: 0.0698 (low).
      *   Is Suspicious: False.
      *   Risk Level: Low.
      *   The extracted URL is `https://automated-mailsender.com/click/d8b8f52f-33b1-4c5b-8a01-fccf8e1d5762`, which matches the sending domain.
  *   **Urgency Check:**
      *   Urgency Label: Not urgent.
      *   Urgency Score: 0.1389 (low).
      *   Risk Contribution: Low.
  *   **Rspamd Scan:** Failed to connect, no verdict available.
  
  **Analyst Inference:**
  Despite the low phishing and urgency scores from the respective tools, the most critical finding is the deceptive sender information. The email explicitly states "From: Intuit" but the actual sending domain is `automated-mailsender.com`, not a legitimate Intuit domain. This is a classic impersonation tactic used in phishing attacks to trick recipients into believing the email is from a trusted source. The presence of a link to "Sign in to your Client Portal" combined with this impersonation strongly suggests an attempt to harvest credentials. The deadline mentioned ("before Friday, Feb 27 at 4:00 pm") is a pressure tactic, even if the urgency tool did not flag it as highly urgent.
  
  **Most Important Findings:**
  1.  **Deceptive Sender Impersonation:** The email falsely claims to be from "Intuit" while originating from `qbo@automated-mailsender.com`, which is not an official Intuit domain. This is a strong indicator of a phishing attempt.
  2.  **Domain Mismatch:** The `From` domain (`automated-mailsender.com`) and `Return-Path` domain (`em8939.automated-mailsender.com`) are inconsistent, adding to the suspicion.
  3.  **Call to Action with Urgency:** The email prompts the user to "Sign in to your Client Portal" with a one-time link and includes a deadline, creating a sense of urgency to act without critical thought.
  
  **Recommended Next Step:**
  This email should be immediately quarantined and reported as a phishing attempt. Users should be advised not to click on any links within the email and to always verify tasks or account information by directly visiting the official website of the service (e.g., QuickBooks/Intuit) or contacting them through known, legitimate channels.

---

### 2. Legitimate (Columbia IT maintenance notice)
**File:** `02_legitimate.eml`

#### Baseline (all 4 skills)
- **Final verdict:** benign
- **rspamd:** score=None / None  risk=None  categories=none
- **header_auth:** risk=low  findings=dmarc_pass
- **urgency_check:** label=not urgent  score=0.1704  contribution=low
- **url_reputation:** phishing_score=0.0075  suspicious=False  risk=low
- **Time:** 66 ms  (4 skills, no LLM)

#### Agent (Gemini 2.5 Flash)
- **Tools called:** rspamd_scan_email, email_header_auth_check (2 call(s))
- **Time:** 46050 ms
- **Tokens:** 8900 in / 1985 out
- **Verdict:**

  Verdict: Benign (High Confidence)
  
  Tool Evidence:
  *   `rspamd_scan_email` failed to connect, so no scanner-backed verdict is available.
  *   `email_header_auth_check` reported a "low" risk level. SPF, DKIM, and DMARC all passed for the `columbia.edu` domain, indicating the email is authentically from Columbia University. The return-path domain and DKIM signing domain also align with `columbia.edu`.
  
  Inference:
  Despite the `rspamd_scan_email` tool failing, the email's authentication headers (SPF, DKIM, DMARC) all passed for the legitimate `columbia.edu` domain. This strongly suggests the email is not spoofed and originates from the stated sender. The content of the email is a standard maintenance notification, which further supports its legitimacy.
  
  Most Important Findings:
  *   All email authentication checks (SPF, DKIM, DMARC) passed for `columbia.edu`.
  *   The email content is consistent with a legitimate IT maintenance notification.
  
  Recommended Next Step:
  No further action is required. The email appears to be legitimate.

---

### 3. Ambiguous (Shopify flash-sale marketing)
**File:** `03_ambiguous_marketing.eml`

#### Baseline (all 4 skills)
- **Final verdict:** benign
- **rspamd:** score=None / None  risk=None  categories=none
- **header_auth:** risk=medium  findings=domain_mismatch, dmarc_pass
- **urgency_check:** label=very urgent  score=0.9282  contribution=high
- **url_reputation:** phishing_score=0.1223  suspicious=False  risk=low
- **Time:** 54 ms  (4 skills, no LLM)

#### Agent (Gemini 2.5 Flash)
- **Tools called:** rspamd_scan_email, urgency_check, url_reputation_check (3 call(s))
- **Time:** 19788 ms
- **Tokens:** 13400 in / 2936 out
- **Verdict:**

  Verdict: Benign (Moderate Confidence)
  
  **Tool Evidence:**
  *   **`rspamd_scan_email`**: Failed to connect, so no scanner-backed verdict is available.
  *   **`urgency_check`**: The email was classified as "somewhat urgent" with an urgency score of 0.9442 (threshold=0.90) and a "high" risk contribution. This is due to phrases like "URGENT FLASH SALE," "72 HOURS ONLY," and "Act now before it's too late!"
  *   **`url_reputation_check`**: The phishing score was 0.0796 (threshold=0.75), indicating a "low" risk level. Two URLs were extracted:
      *   `https://deals.shopify-partner-network.com/track?uid=jw4822&src=email&campaign=flash_feb26`
      *   `https://deals.shopify-partner-network.com/unsubscribe?uid=jw4822`
      Both URLs point to a subdomain of `shopify-partner-network.com`.
  *   **Email Headers (Manual Inspection)**: `dkim=pass`, `spf=pass`, and `dmarc=pass` for `shopify-partner-network.com` indicate strong authentication.
  
  **Inference:**
  Despite the aggressive urgency language flagged by the `urgency_check` tool, the email exhibits strong authentication results (SPF, DKIM, DMARC all pass) and the URLs point to a legitimate subdomain of `shopify-partner-network.com` with a low phishing risk. This suggests the email is a legitimate marketing communication from Shopify's partner network, rather than a malicious attempt. The urgency is likely a marketing tactic to encourage immediate action.
  
  **Most Important Findings:**
  *   Strong email authentication (SPF, DKIM, DMARC pass).
  *   URLs are legitimate and show low phishing risk.
  *   High urgency language is used, which is a common marketing tactic but can also be a social engineering indicator.
  
  **Recommended Next Step:**
  No immediate security action is required. The email appears to be a legitimate promotional offer. The recipient can decide whether to engage with the content.

---

### 4. Spear Phishing (Columbia IT security alert)
**File:** `04_spear_phishing.eml`

#### Baseline (all 4 skills)
- **Final verdict:** suspicious
- **rspamd:** score=None / None  risk=None  categories=none
- **header_auth:** risk=high  findings=dmarc_fail, spf_not_pass, dkim_not_pass
- **urgency_check:** label=somewhat urgent  score=0.9794  contribution=high
- **url_reputation:** phishing_score=0.0776  suspicious=False  risk=low
- **Time:** 44 ms  (4 skills, no LLM)

#### Agent (Gemini 2.5 Flash)
- **Tools called:** rspamd_scan_email, email_header_auth_check, urgency_check, url_reputation_check (4 call(s))
- **Time:** 56258 ms
- **Tokens:** 15416 in / 3532 out
- **Verdict:**

  **Verdict: Phishing (High Confidence)**
  
  **Tool Evidence:**
  
  *   **Email Header Authentication Check:**
      *   **Risk Level:** High
      *   **DMARC:** Fail
      *   **SPF:** Softfail
      *   **DKIM:** Fail
      *   *Inference:* These critical authentication failures indicate that the email is not legitimately from `columbia-university.net`, despite the sender address appearing to be from that domain. This is a strong indicator of email spoofing.
  
  *   **Urgency Check:**
      *   **Urgency Label:** Somewhat urgent
      *   **Urgency Score:** 0.9794 (high)
      *   **Risk Contribution:** High
      *   *Inference:* The email employs pressure tactics with phrases like "[ACTION REQUIRED]", "You must verify your identity within 24 hours or your account will be suspended," and "verify your identity immediately." This is a common social engineering technique used in phishing attacks.
  
  *   **URL Reputation Check:**
      *   **Phishing Score:** 0.0776
      *   **Is Suspicious:** False
      *   **Risk Level:** Low
      *   **Extracted URL:** `https://columbia-university.net/secure/verify?token=eyJhbGciOiJIUzI0NiJ9.jw4822`
      *   *Inference:* While the URL itself did not trigger a high phishing score from the tool, likely because the domain `columbia-university.net` is not inherently blacklisted, the context of the email (authentication failures and urgency) strongly suggests that this URL is part of a phishing attempt designed to harvest credentials. The domain `columbia-university.net` is a deceptive look-alike for the legitimate `columbia.edu` domain.
  
  **Analyst's Inference:**
  The combination of severe email authentication failures (DMARC, SPF, DKIM all failing) and the use of high-pressure urgency tactics to compel the recipient to click a link strongly indicates a phishing attempt. The sender is spoofing a legitimate-looking domain to trick the recipient into believing the email is from Columbia University IT Security. The URL, while appearing to be on the spoofed domain, is designed to lead the user to a malicious site.
  
  **Most Important Findings:**
  1.  **Authentication Failures:** The email failed DMARC, SPF, and DKIM checks, confirming it is not from the claimed sender domain.
  2.  **Urgency and Coercion:** The email uses a high-urgency subject and body text to create fear and pressure the recipient into immediate action.
  
  **Recommended Next Step:**
  Quarantine this email immediately and notify the recipient that it is a phishing attempt. Consider blocking emails from the `columbia-university.net` domain and investigate if this domain is newly registered or known for malicious activity.

---

## Comparison Charts

### Latency (ms)

| Email | Baseline (4 skills) | Agent |
|-------|---------------------|-------|
| Obvious Phishing (QuickBooks impersonation) | 3507 | 25251 |
| Legitimate (Columbia IT maintenance notice) | 66 | 46050 |
| Ambiguous (Shopify flash-sale marketing) | 54 | 19788 |
| Spear Phishing (Columbia IT security alert) | 44 | 56258 |

### Skill Calls per Email

| Email | Baseline | Agent (adaptive) | Skills Agent skipped |
|-------|----------|-----------------|----------------------|
| Obvious Phishing (QuickBooks impersonation) | 4 | 4 (rspamd_scan_email, email_header_auth_check, url_reputation_check, urgency_check) | — |
| Legitimate (Columbia IT maintenance notice) | 4 | 2 (rspamd_scan_email, email_header_auth_check) | urgency_check, url_reputation_check |
| Ambiguous (Shopify flash-sale marketing) | 4 | 3 (rspamd_scan_email, urgency_check, url_reputation_check) | email_header_auth_check |
| Spear Phishing (Columbia IT security alert) | 4 | 4 (rspamd_scan_email, email_header_auth_check, urgency_check, url_reputation_check) | — |

### Baseline: ML Skill Signals

| Email | Urgency Label | Urgency Score | URL Phishing Score | URL Suspicious |
|-------|--------------|---------------|--------------------|----------------|
| Obvious Phishing (QuickBooks impersonation) | not urgent | 0.139 | 0.070 | False |
| Legitimate (Columbia IT maintenance notice) | not urgent | 0.170 | 0.007 | False |
| Ambiguous (Shopify flash-sale marketing) | very urgent | 0.928 | 0.122 | False |
| Spear Phishing (Columbia IT security alert) | somewhat urgent | 0.979 | 0.078 | False |

### Token Usage (Agent only)

| Email | Tokens In | Tokens Out | Total |
|-------|-----------|------------|-------|
| Obvious Phishing (QuickBooks impersonation) | 18444 | 3476 | 21920 |
| Legitimate (Columbia IT maintenance notice) | 8900 | 1985 | 10885 |
| Ambiguous (Shopify flash-sale marketing) | 13400 | 2936 | 16336 |
| Spear Phishing (Columbia IT security alert) | 15416 | 3532 | 18948 |