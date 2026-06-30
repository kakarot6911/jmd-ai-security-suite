# 🛡️ JMD Security Suite

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

## Quickstart

```bash
./run.sh setup     # install deps (already done)
./run.sh data      # build BreachRadar corpus (already done)
./run.sh test      # run all 38 tests
./run.sh demo      # CLI demo of the four suite tools

# individual dashboards (also available standalone)
./run.sh resumeshield   # / siteguard / linkguard / breachradar
```

### REST API endpoints
`GET /health` · `GET /tools` · `POST /phishguard/analyze` · `POST /resumeshield/redact`
· `POST /siteguard/scan` · `POST /linkguard/analyze` · `POST /breachradar/check`
· `GET /breachradar/scan-org`

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
Lexical safety analysis of a single URL — **purely offline, no network calls**.
- Flags **typosquats** (edit-distance lookalikes of `jmdcareermaker.com`), **brand-in-subdomain**
  burials, **`user@host` credential traps**, **punycode/homograph** hosts, URL **shorteners**,
  suspicious TLDs, label stuffing, non-HTTPS, and sensitive paths.
- Verdict (SAFE / SUSPICIOUS / DANGEROUS) + 0–100 risk score, every signal explained, plus advice.
- Complements PhishGuard: PhishGuard scores the e-mail *body*, LinkGuard scrutinises the *links*.
- `python -m linkguard.cli check "http://bit.ly/jmd-offer"` · `... demo` · `streamlit run linkguard/app.py`

## 📡 BreachRadar — `breachradar/`
Credential-exposure monitor over a **local, synthetic** breach corpus (offline & safe).
- **Privacy-preserving k-anonymity** hash-prefix lookup (HIBP range-API model).
- Risk scoring by breach severity, recency, password exposure, and high-value role.
- Org-wide scan + per-account remediation advice.
- `python -m breachradar.cli scan-org` · `streamlit run breachradar/app.py`

---

## 🤖 Role of AI
How AI/ML is used in the suite and how it strengthens the firm's security posture —
honestly separating today's ML (PhishGuard), AI-shaped automation, and the roadmap —
is written up in **[`reports/AI_IN_SECURITY.md`](reports/AI_IN_SECURITY.md)**.

## Design principles
- **Explainable:** every verdict lists the concrete signals behind it.
- **Safe by default:** no destructive actions; live scanning requires authorization;
  breach data is synthetic; PII is redacted, never stored.
- **Tested:** 38 standalone tests (`./run.sh test`), no network required.
- **Reproducible:** seeded datasets, pinned deps, Python 3.14.

## Honest scope note
Datasets/corpora here are synthetic so the suite is self-contained and reproducible.
The transferable value is the detection logic, the privacy-preserving design, and the
analyst workflow — all of which apply directly to real candidate data, real domains,
and a real breach feed when connected.
