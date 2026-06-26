# Technical Report — JMD Security Suite

**Author:** Fazal Ahmad — AI Cybersecurity Intern
**Organisation:** JMD The Career Maker
**Reporting to:** AI & Cybersecurity Team Lead
**Version:** 1.0 · **Status:** All modules operational · 27/27 automated tests passing

---

## 1. Executive summary

JMD The Career Maker is a career-solutions firm whose core operations — recruiter
email, offer letters, candidate documents, and online portals — are exactly the
surfaces targeted by modern attackers. This suite delivers **four AI/cybersecurity
controls**, unified behind a single premium **Security Console** and a single REST
**API**, that together address the firm's most material risks:

| Module | Risk addressed | Internship duty |
|---|---|---|
| 🛡️ PhishGuard | Fake job offers / recruitment scams / phishing impersonating the firm | AI-driven threat detection |
| 🪪 ResumeShield | Candidate PII exposure when sharing resumes (DPDP Act 2023) | Security automation w/ AI-ML |
| 🔐 SiteGuard | Web mis-configuration & secret exposure on site/portal | Vulnerability assessment |
| 📡 BreachRadar | Staff/recruiter credentials exposed in breaches | Threat intelligence / SOC |

Every module is **explainable**, **safe by default**, and **tested**.

---

## 2. Architecture

```
                 ┌──────────────────────────────────────────┐
                 │      JMD Security Console (Streamlit)      │  premium UI
                 │   Overview · Phish · Resume · Site · Breach│
                 └───────────────────┬──────────────────────┘
                                     │  console.integrations  (one adapter)
        ┌───────────────┬────────────┼──────────────┬────────────────┐
        ▼               ▼            ▼               ▼                ▼
   PhishGuard     ResumeShield    SiteGuard      BreachRadar     FastAPI (api.main)
   (TF-IDF+LR)    (PII+DPDP)      (posture)      (k-anon)        same adapter → REST
```

- **`console/integrations.py`** is the single source of truth: both the UI and the
  API call the same functions, so behaviour can never drift between them (enforced by
  `test_integration_adapter_consistency`).
- PhishGuard lives in its own project (`~/jmd_phishguard`) and is loaded
  cross-project; the suite degrades gracefully if its model is absent.

---

## 3. Module design notes

### 3.1 PhishGuard
Fusion of a TF-IDF + LogisticRegression language model with 13 deterministic security
rules. The rules double as the analyst-facing explanation and as **hard-block kill
switches** (fee/credential/crypto tactics escalate regardless of model score).

### 3.2 ResumeShield
India-aware PII detection with **validation to suppress false positives**: Aadhaar via
the **Verhoeff checksum**, payment cards via **Luhn**, bank accounts gated on
account-context keywords. Produces a redacted document, an exposure risk band, an audit
log, and a **DPDP Act 2023 compliance report** with a "safe-to-share" verdict.

### 3.3 SiteGuard
Passive, non-intrusive posture scan: security headers (HSTS, CSP, X-Frame-Options …),
cookie flags, banner leakage, TLS version, and probes for exposed files
(`/.git/config`, `/.env`). The header-analysis core is a **pure function** (fully unit
tested offline). **Live scanning is gated behind an explicit authorization flag** and
limited to safe GET requests — the API returns **403** for unauthorized live scans.

### 3.4 BreachRadar
Credential-exposure monitoring using a **k-anonymity hash-prefix lookup** (the HIBP
range-API model): only a 5-char SHA-1 prefix would ever leave the client; the full hash
is matched locally. Risk scoring blends breach severity, recency, password exposure and
high-value-role targeting. The corpus is **synthetic and offline**.

---

## 4. Security & safety posture of the tooling itself
- No destructive operations anywhere.
- Live web scanning requires explicit operator authorization (default deny).
- Breach data is synthetic; no real breach corpora are downloaded.
- Candidate PII is redacted in-memory and never persisted by the tools.
- All datasets are seeded and reproducible; dependencies are pinned (Python 3.14).

---

## 5. Validation

| Suite | Tests | Result |
|---|---|---|
| ResumeShield | 7 | ✅ |
| SiteGuard | 7 | ✅ |
| BreachRadar | 6 | ✅ |
| Integration / API | 7 | ✅ |
| **Total** | **27** | **✅ all passing** |

Run with `./run.sh test`. The unified API was additionally verified end-to-end across
all endpoints (`/health`, `/phishguard/analyze`, `/resumeshield/redact`,
`/siteguard/scan`, `/breachradar/check`, `/breachradar/scan-org`), including the 403
authorization guard.

---

## 6. Limitations & roadmap
- Datasets/corpora are synthetic → metrics validate the pipeline, not field difficulty.
- Next: connect a real reported-scam feed, real email headers (SPF/DKIM/DMARC), URL
  reputation, a real breach feed (e.g. an internal HIBP-style mirror), and
  Hindi/Hinglish coverage.
- Add authentication + rate limiting to the API before any non-local deployment.
- Containerise (Dockerfile) and add CI to run the 27 tests on every change.

---

## 7. Conclusion
The suite demonstrates production-shaped, explainable, defence-in-depth security
controls tailored to JMD's business, unified behind one premium console and one API,
with a clean path from the current synthetic build to real data sources.
