# JMD Security Suite — one-page pitch

**Role:** AI Cybersecurity Intern · **JMD The Career Maker**
**Repo:** https://github.com/kakarot6911/jmd-ai-security-suite (MIT, public)

## The idea
A career-consulting firm handles two sensitive things at scale: **candidate personal
data** and **its own brand/trust** in the eyes of job-seekers. I built five tools that
each defend one concrete failure mode a firm like JMD actually faces — not toy demos,
but the detection logic, privacy-preserving design and analyst workflow a real SOC would use.

## The five tools → real firm risks

| Tool | Risk it removes | AI/ML angle |
|------|-----------------|-------------|
| 🪪 **ResumeShield** | Resumes leak Aadhaar/PAN/bank data — a DPDP Act 2023 liability | Validated PII detection (Verhoeff, Luhn) + compliance reporting |
| 🔐 **SiteGuard** | The firm's site/portal leaks secrets or misses security headers | Automated posture grading (A–F) with prioritised fixes |
| 🔗 **LinkGuard** | Job links impersonate the firm (typosquats, shorteners, homographs) | **Trained ML classifier** (TF-IDF + logistic regression) fused with heuristics |
| 📡 **BreachRadar** | Recruiter/HR accounts already exposed in breaches | Privacy-preserving k-anonymity lookup (HIBP model) |
| 🛡️ **PhishGuard** | Fake job offers / recruitment-fraud emails | ML text classifier (separate repo, integrated) |

## Why it stands out as intern work
- **Maps 1:1 to the appointment-letter duties** — threat detection, vulnerability
  assessment, security automation with AI/ML, threat intelligence, technical reports.
- **Production-shaped, not a notebook** — unified REST API + premium console + interactive
  website, one shared adapter so they can't drift.
- **Secure by construction** — API-key auth, rate limiting, security headers, input caps,
  non-root Docker image; live scans gated behind explicit authorization.
- **Honest about scope** — datasets are synthetic and seeded (reproducible); the ML metrics
  carry that caveat. The *transferable asset* is the logic and design, ready for real data.
- **Deployable today** — one-click Render blueprint + Streamlit Cloud (`DEPLOY.md`).
- **54 automated tests**, all passing, no network required.

## Try it in 30 seconds
```bash
git clone https://github.com/kakarot6911/jmd-ai-security-suite && cd jmd-ai-security-suite
./run.sh setup && ./run.sh test        # 54/54 green
./run.sh web                           # website + API → http://localhost:8000/docs
```

## What I'd build next on the job
Wire a real breach feed (HIBP), live TLS/DNS intelligence for LinkGuard, SSO/audit on the
API, and a scheduled scan → alerting loop — turning the suite from a portfolio piece into a
standing internal security service.
