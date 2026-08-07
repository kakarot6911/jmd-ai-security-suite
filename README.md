# 🛡️ JMD Security Suite

![tests](https://img.shields.io/badge/tests-70%20passing-brightgreen)
![python](https://img.shields.io/badge/python-3.14-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![docker](https://img.shields.io/badge/docker-ready-2496ED)
![API](https://img.shields.io/badge/API-key%20auth%20%2B%20rate%20limited-orange)

**Four AI/cybersecurity tools built for the AI Cybersecurity internship at
JMD The Career Maker** — each one targets a *real* operational risk for a
career-consulting firm and maps directly to the appointment-letter duties
(*AI-driven threat detection, vulnerability assessments, security automation
with AI/ML, threat intelligence, SOC workflows, technical reports*).

| Tool | Organisational problem it solves | Maps to duty |
|---|---|---|
| 🪪 **ResumeShield** | Candidate resumes are full of PII (Aadhaar, PAN, bank a/c) that must be protected before sharing with employers — a **DPDP Act 2023** legal duty. | Security automation w/ AI-ML |
| 🔐 **SiteGuard** | The firm's website & candidate portal may leak secrets or miss security headers. | Vulnerability assessment |
| 🔗 **LinkGuard** | Job links e-mailed to/from candidates may be typosquats, shorteners or lookalikes impersonating the firm. | AI threat detection |
| 📡 **BreachRadar** | Staff/recruiter accounts (HR, careers, finance) may already be exposed in data breaches. | Threat intelligence / SOC |

> A complementary fifth tool, **PhishGuard** (recruitment-fraud & phishing
> detection), lives in a separate repo: [`jmd-phishguard`](https://github.com/gdfazal/jmd-phishguard).
> The unified console & API integrate all five.

![JMD Security Console — unified dashboard showing live output from all five tools](docs/website.png)

---

## ⭐ Interactive website

A fast, premium **single-page web app** (vanilla JS, animated SVG gauges, live `fetch`
to the API — no page reloads) is served directly by the FastAPI backend:

```bash
cd ~/jmd_security_suite
./run.sh web       # 🌐 interactive website + API → http://localhost:8000
```

There is also a Streamlit version of the console:

```bash
./run.sh console   # 🛡️ premium Streamlit dashboard → http://localhost:8501
./run.sh api       # REST API only (also serves the website) → http://localhost:8000/docs
```

The console has an **Overview** page (live KPIs + tool cards + exposure snapshot) and a
dedicated page per tool. Both console and API call one shared adapter
(`console/integrations.py`), so they can never drift apart.

## 🐳 Run anywhere (Docker)

The whole suite (website + REST API) ships as one container — nothing to install:

```bash
./run.sh docker          # build the image and serve on http://localhost:8000
# or manually:
docker build -t jmd-security-suite .
docker run --rm -p 8000:8000 jmd-security-suite
```

The image runs as a non-root user and exposes a `/health` healthcheck. PhishGuard is a
separate repo and isn't bundled (the suite degrades gracefully); to include it, mount it
and set `PHISHGUARD_ROOT` — see the [Dockerfile](Dockerfile) header.

## ☁️ Deploy live

[![Deploy to Render](https://img.shields.io/badge/Deploy%20to-Render-46E3B7?logo=render&logoColor=white)](https://render.com/deploy?repo=https://github.com/kakarot6911/jmd-ai-security-suite)

The website + API deploy to **Render** as a Docker Blueprint (`render.yaml`), and the
Streamlit console to **Streamlit Community Cloud** — both free. Full click-by-click
steps, including the auto-generated API key, are in **[`DEPLOY.md`](DEPLOY.md)**. The
container honours the host-injected `$PORT`, so Railway / Fly.io / Koyeb work too.

## 🔒 API hardening

The unified API is production-shaped, all configured by environment variables
(defaults keep local dev frictionless — see [`DEPLOY.md`](DEPLOY.md)):

- **API-key auth** on every analysis endpoint — set `JMD_API_KEY` and callers must send
  `X-API-Key` (constant-time compared). Unset ⇒ open, for local use. Metadata routes stay open.
- **Rate limiting** — in-memory sliding window, per API key (else per IP): `429` + `Retry-After`.
- **Security headers** on every response — CSP, `X-Frame-Options: DENY`, `nosniff`, referrer & permissions policy.
- **Input caps** — request-body size limit (`413`) and per-field length limits (`422`).
- **CORS** — configurable allowed origins.

Verified by 11 dedicated tests in `api/tests/test_security.py`.

## Quickstart

```bash
./run.sh setup     # install deps (already done)
./run.sh data      # build BreachRadar corpus (already done)
./run.sh test      # run all 70 tests
./run.sh demo      # CLI demo of the four suite tools

# individual dashboards (also available standalone)
./run.sh resumeshield   # / siteguard / linkguard / breachradar
```

### REST API endpoints
`GET /health` · `GET /version` · `GET /tools` · `POST /phishguard/analyze` · `POST /resumeshield/redact`
· `POST /siteguard/scan` · `POST /linkguard/analyze` · `POST /breachradar/check`
· `GET /breachradar/scan-org` · `GET /breachradar/range/{prefix}` (live HIBP)
· `GET /breachradar/catalogue` (live HIBP) · `POST /breachradar/live-check` (needs `HIBP_API_KEY`)
— interactive Swagger docs at `/docs`.
The `POST` analysis routes require an `X-API-Key` header when `JMD_API_KEY` is set (see [API hardening](#-api-hardening)).

---

## 🪪 ResumeShield — `resumeshield/`
Detects & redacts PII from candidate documents and emits a **DPDP compliance report**.
- India-aware detectors with validation: **Aadhaar (Verhoeff checksum)**, PAN, GSTIN,
  passport, **credit card (Luhn)**, bank account (context-gated), email, phone, DOB, PIN.
- Risk score + band, redacted output, audit log, "safe-to-share" verdict.
- `python -m resumeshield.cli resume.pdf` · `streamlit run resumeshield/app.py`

## 🔐 SiteGuard — `siteguard/`
Passive, **non-intrusive** web security-posture scanner for domains you control.
- Checks security headers (HSTS, CSP, X-Frame-Options…), cookie flags, banner leakage,
  TLS version, and probes for exposed files (`/.git/config`, `/.env`).
- Letter-grade (A–F) posture score with prioritised, remediation-first findings.
- Live scans are **gated behind an explicit authorization flag**; an offline demo mode
  needs no network.
- `python -m siteguard.cli --demo vulnerable` · `... https://yourdomain.com --authorize`

## 🔗 LinkGuard — `linkguard/`
Safety analysis of a single URL — **purely offline, no network calls** — fusing
heuristics with a **trained ML classifier**.
- Flags **typosquats** (edit-distance lookalikes of `jmdcareermaker.com`), **brand-in-subdomain**
  burials, **`user@host` credential traps**, **punycode/homograph** hosts, URL **shorteners**,
  suspicious TLDs, label stuffing, non-HTTPS, and sensitive paths.
- **Machine learning:** a `char_wb` TF-IDF + lexical-feature **LogisticRegression** model
  (`linkguard/model.py`) scores each URL's malicious probability and fuses it with the
  heuristics — **skipped for the genuine domain** so real links are never penalised.
  Trained on seeded synthetic data: `./run.sh train` (metrics in `linkguard/models/metrics.json`).
- Verdict (SAFE / SUSPICIOUS / DANGEROUS) + 0–100 risk score, every signal explained, plus advice.
- Complements PhishGuard: PhishGuard scores the e-mail *body*, LinkGuard scrutinises the *links*.
- `python -m linkguard.cli check "http://bit.ly/jmd-offer"` · `... demo` · `streamlit run linkguard/app.py`

## 📡 BreachRadar — `breachradar/`
Credential-exposure monitor over a **local, synthetic** breach corpus (offline & safe).
- **Privacy-preserving k-anonymity** hash-prefix lookup (HIBP range-API model).
- Risk scoring by breach severity, recency, password exposure, and high-value role.
- Org-wide scan + per-account remediation advice.
- `python -m breachradar.cli scan-org` · `streamlit run breachradar/app.py`

### 🌐 Live mode — real breach data (`breachradar/live.py`)
The synthetic corpus stays the default so demos and tests are deterministic. Alongside it,
BreachRadar connects to the **real** Have I Been Pwned register using the two endpoints that
are free and keyless:

| Capability | Endpoint | Real? | Key needed |
|---|---|---|---|
| Password exposure (k-anonymity) | `GET /breachradar/range/{prefix5}` | ✅ live | none |
| Breach register + statistics | `GET /breachradar/catalogue` | ✅ live, 24h cached | none |
| Per-account breach lookup | `POST /breachradar/live-check` | ✅ live | `HIBP_API_KEY` (paid) |

**The password check is genuinely private.** The browser hashes the password with
SubtleCrypto, sends only the **first 5 hex characters** of the SHA-1 upstream, and matches the
remaining 35 locally. Neither this server nor HIBP can determine which password was tested —
that is the k-anonymity model the synthetic corpus was already modelled on, now pointed at the
real thing. Typing `password123` returns its true count of **2,266,543** sightings.

Operational safeguards: 10s timeouts, one polite retry (incl. on HIBP's 429), a 24h on-disk
cache so normal use makes no network calls, and every failure raised as `LiveDataUnavailable`
so callers fall back to synthetic data instead of erroring. The paid lookup refuses to run
without a key rather than returning a false "clean" result. All 16 live-layer tests inject a
stub fetcher, so `./run.sh test` still needs no network.

---

## 🤖 Role of AI
How AI/ML is used in the suite and how it strengthens the firm's security posture —
honestly separating today's ML (PhishGuard), AI-shaped automation, and the roadmap —
is written up in **[`reports/AI_IN_SECURITY.md`](reports/AI_IN_SECURITY.md)**.

## 📊 Measured accuracy

Accuracy is measured, not asserted. `eval/cases.py` holds 106 hand-labelled cases —
real Indian recruitment-scam patterns, real resume layouts, real header configurations —
including deliberate false-positive traps (a salary of `500000` is not a PIN code;
`we pay 12 LPA` is not a demand for money; `/accounting` is not `/account`).

```bash
./run.sh eval        # accuracy vs labelled cases, lists every individual miss
./run.sh holdout     # held-out cases, never tuned against
./run.sh fuzz        # hostile input must never crash a tool
```

| Tool | Before | After | What was wrong |
|---|---:|---:|---|
| PhishGuard | 76.9% | **100%** | `immediately` alone triggered urgency; a gmail recruiter with no company claim scored as fraud; the ML model could assert fraud with **zero** red flags |
| ResumeShield | 47.8% | **100%** | any 6-digit number read as a PIN code (salaries, scores, headcounts); any `A1234567` read as a passport; no IFSC/UAN/voter-ID/UPI/DL detectors |
| SiteGuard | 44.4% | **100%** | a *present* header counted as a *good* header — `max-age=0`, `default-src *` and `X-Frame-Options: ALLOWALL` all scored as fully protected |
| LinkGuard | 93.5% | **100%** | `javascript:`/`data:` URLs **crashed** the analyzer; scheme-less pastes were called insecure; unicode homoglyphs missed |
| BreachRadar | 72.7% | **100%** | the same breach counted twice, saturating three accounts at exactly 100/100 so the org scan could not rank them |
| **Overall** | **71.3%** | **100%** | 18 false positives and 7 false negatives eliminated |

Held-out generalisation: **29/29** on cases written after the fixes and run once.

**Read that 100% correctly.** It means the suite now handles every labelled case, not
that it is perfect on the open world — 106 cases is a small set, and cases.py was written
by the same hand that fixed the code. The honest claims are the *before/after deltas* and
the specific defect classes closed. Two changes matter beyond the score:

- **PhishGuard can no longer assert fraud without evidence.** The synthetic-trained model
  was over-confident (0.81 on a routine interview-scheduling email). The verdict is now a
  calibration of model score and fired rules, capped below the fraud threshold when no
  deterministic rule fires — a verdict with an empty red-flag list cannot be justified to
  a candidate, so it is no longer issued.
- **SiteGuard grades header *values*, not their presence.** A neutered header is worse
  than a missing one because it passes a checklist scan.

### Robustness
`./run.sh fuzz` drives every tool with empty values, wrong types, 100k-character strings,
null bytes, unicode, path traversal, template-injection and malformed URLs — **202 hostile
inputs, zero unhandled exceptions**. Every API route was fuzzed live too: every hostile
request returned a valid HTTP status (200/400/422), never a 500.

## Design principles
- **Explainable:** every verdict lists the concrete signals behind it.
- **Safe by default:** no destructive actions; live scanning requires authorization;
  breach data is synthetic; PII is redacted, never stored.
- **Measured:** accuracy is evaluated against labelled cases, not claimed (`./run.sh eval`).
- **Tested:** 70 standalone tests (`./run.sh test`), no network required — the live-data
  layer is tested through an injected fetcher.
- **Hardened:** the API ships with key auth, rate limiting, security headers and input caps.
- **Reproducible:** seeded datasets, pinned deps, Python 3.14.

## Honest scope note
Most corpora here are synthetic so the suite is self-contained and reproducible — and three
of the five tools already operate on real input by design: **ResumeShield** redacts real
resumes, **SiteGuard** scans real domains once authorized, and **LinkGuard**'s lexical
analysis works on any real URL. **BreachRadar** now also queries the real HIBP register
(see [Live mode](#-live-mode--real-breach-data-breachradarlivepy)).

What remains synthetic: PhishGuard's ML training corpus and LinkGuard's URL model (their
reported metrics are therefore optimistic — the deterministic rules carry the real weight),
and BreachRadar's default per-account corpus, since email→breach lookup is a paid HIBP tier.
