# JMD Security Suite — Work Report & Student-Protection Case

**Author:** Fazal Ahmad — AI Cybersecurity Intern
**Organisation:** JMD The Career Maker (education & career consultancy)
**Date:** 30 July 2026
**Status:** Console live · 54/54 automated tests passing · API hardened · repo public

---

## 1. What was verified today

| Check | Result |
|---|---|
| Unified Security Console (`./run.sh console`) | ✅ Running, HTTP 200 on `http://localhost:8501` |
| Full test suite (`./run.sh test`) | ✅ **54/54 passing** |
| All five tools loaded through one adapter | ✅ `PhishGuard, ResumeShield, SiteGuard, LinkGuard, BreachRadar` |
| End-to-end CLI demo (`./run.sh demo`) | ✅ All modules produced live, explainable verdicts |
| Working tree | ✅ Clean, synced with `origin/main` |

Everything in this report is backed by output captured from the running system today,
not from documentation.

---

## 2. The work done

### 2.1 Five security tools

| # | Tool | What it does | Core technique |
|---|---|---|---|
| 1 | 🛡️ **PhishGuard** | Reads a message/offer letter and judges whether it is a recruitment scam | TF-IDF + Logistic Regression **fused with 13 deterministic rules**; fee/credential/crypto tactics act as hard-block kill switches |
| 2 | 🪪 **ResumeShield** | Finds and redacts personal data in a student's resume; produces a DPDP Act 2023 compliance verdict | India-aware PII detection with **validation** — Aadhaar via Verhoeff checksum, cards via Luhn, bank a/c context-gated |
| 3 | 🔐 **SiteGuard** | Passive security-posture scan of the firm's site/portal | Header/cookie/TLS analysis as a **pure function**; live scanning default-deny behind an explicit authorization flag |
| 4 | 🔗 **LinkGuard** | Scores the *links* inside a job message without ever visiting them | ~12 lexical heuristics (typosquat via edit distance, brand-in-subdomain, `user@host` traps, punycode homographs, shorteners, suspicious TLDs) **plus a trained `char_wb` TF-IDF + lexical LogisticRegression classifier** |
| 5 | 📡 **BreachRadar** | Flags staff/counsellor accounts whose credentials appear in breach dumps | **k-anonymity SHA-1 prefix lookup** (HIBP range model) over a local corpus; risk scored by severity, recency, password exposure and role value |

### 2.2 The unified layer that makes it a product, not five scripts

- **`console/integrations.py`** — one adapter that both the UI *and* the REST API call.
  Behaviour physically cannot drift between them, and a test
  (`test_integration_adapter_consistency`) enforces it.
- **`console/app.py`** — a premium dark Streamlit console: an Overview dashboard plus a
  dedicated page per tool, with a shared design system (`theme.py`) — KPI cards, risk
  badge pills, gradient hero.
- **`api/main.py`** — one FastAPI service exposing every tool over REST
  (`/phishguard/analyze`, `/resumeshield/redact`, `/siteguard/scan`,
  `/linkguard/analyze`, `/breachradar/check`, `/breachradar/scan-org`, plus
  `/health`, `/version`, `/tools`).
- **`web/`** — an interactive public website served by the same API.

### 2.3 Production hardening (v1.1.0)

`api/security.py` provides pure, testable primitives wired into a single `harden()`
middleware, applied in order: **body-size cap (413) → API-key auth (401) →
rate limit (429) → security headers**.

- Constant-time API-key comparison (`X-API-Key`), env-gated — unset means auth off, so
  the public demo still works.
- Sliding-window per-client rate limiter with `Retry-After`.
- Security headers including a CSP that whitelists Google Fonts.
- Per-field length caps (422) and configurable CORS.
- All knobs are environment variables: `JMD_API_KEY`, `JMD_RATE_LIMIT/WINDOW`,
  `JMD_CORS_ORIGINS`, `JMD_MAX_BODY_BYTES`.

### 2.4 Packaging, deployment and publication

- **Dockerfile** — `python:3.14-slim`, non-root user, healthcheck, honours `$PORT`.
- **One-click deploy** — `render.yaml` blueprint, `Procfile`, `DEPLOY.md`.
- **Public repository** — MIT licensed, secret-scanned before publishing, 10 topics:
  **https://github.com/kakarot6911/jmd-ai-security-suite**
- **Dispatcher** — `./run.sh {setup|data|train|test|demo|console|api|web|docker|<tool>}`.

### 2.5 Test coverage

| Suite | Tests |
|---|---|
| ResumeShield | 7 |
| SiteGuard | 7 |
| LinkGuard — heuristics | 8 |
| LinkGuard — ML model | 5 |
| BreachRadar | 6 |
| API hardening (auth / rate limit / headers / size) | 11 |
| Integration & API routes | 10 |
| **Total** | **54 — all passing** |

---

## 3. Evidence — live output captured today

**PhishGuard** on a classic fake-offer message ("pay ₹4,500 refundable registration fee,
send Aadhaar and bank details within 24 hours"):

```
fraud_probability : 0.9922
risk_band         : CRITICAL
recommended_action: Block & alert candidate
hard_block        : true
flags             : upfront_payment  (1.00) — Asks the candidate to PAY money — legitimate employers never do this.
                    urgency_pressure (0.45) — Uses urgency/scarcity pressure.
```

**LinkGuard** on seven sample job links — 1 safe, 6 dangerous, each with a plain-English reason:

```
✓ SAFE      score=  0  jmdcareermaker.com
⛔DANGEROUS score= 87  jmdcaremaker.com              → 2 edits from the official domain — a lookalike
⛔DANGEROUS score= 82  jmdcareermaker.com.secure-login.ru → brand buried in a subdomain; real domain is secure-login.ru
⛔DANGEROUS score=100  ...@192.168.0.5               → real destination hidden after an '@'; secret leaked in query
⛔DANGEROUS score= 82  xn--jmdcareermker-9zb.com     → punycode homograph
⛔DANGEROUS score=100  jmd-careermaker-hr.xyz        → brand embedded in a throwaway .xyz domain
⛔DANGEROUS score= 79  bit.ly/...                    → shortener hides the true destination
```

**ResumeShield** on a sample student resume:

```
RISK: 83 CRITICAL
INVENTORY: NAME, EMAIL, PHONE, AADHAAR, PAN, BANK_ACCOUNT, DOB, PIN_CODE
Aadhaar: [AADHAAR:••••6015]   PAN: [PAN:••••234F]   A/c [BANK_ACCOUNT:••••9012]
COMPLIANT TO SHARE AS-IS: False
```

**SiteGuard** on the vulnerable demo target: **Grade F**, posture 0/100, 11 findings
including exposed `/.git/config` and `/.env`.

**BreachRadar** org scan: **6 of 8 accounts exposed, 4 at HIGH/CRITICAL** — including
`hr@`, `info@` and `careers@`, the exact mailboxes students trust.

---

## 4. How this protects JMD the consultancy — and the students

### 4.1 The problem, stated plainly

An education/career consultancy is a **trust brokerage**. A student hands over their
documents, their money and their future plans on the strength of the firm's name. That
makes the firm's name the most valuable thing a scammer can steal. The classic
education-consultancy fraud runs like this:

1. A scammer registers `jmdcaremaker.com` or `jmd-careermaker-hr.xyz`.
2. They mail students an "offer letter" or "admission confirmation" on JMD letterhead.
3. They demand a "registration / visa processing / seat-blocking fee".
4. They collect Aadhaar, PAN, passport and bank details "for verification".
5. The student loses money and identity; **the firm loses its reputation** and inherits
   the complaint.

Note that steps 1–5 never touch JMD's servers. That is exactly why a firewall does not
help here, and why this suite attacks the *communication* layer instead.

### 4.2 Which tool intercepts which stage

| Stage of the scam | Tool | What it does at that moment |
|---|---|---|
| **0. Attacker researches the firm** | 📡 BreachRadar | Flags counsellor/HR accounts already leaked, so passwords are rotated and MFA enforced **before** the attacker uses a real inbox to mail students |
| **1. Lookalike domain registered** | 🔗 LinkGuard | Edit-distance typosquat detection catches `jmdcaremaker.com`; brand-in-subdomain catches `jmdcareermaker.com.secure-login.ru`; punycode catches homographs |
| **2. Fake offer letter sent** | 🛡️ PhishGuard | Reads the message and returns CRITICAL with named red flags — an answer the student can *understand*, not just a score |
| **3. Fee demanded** | 🛡️ PhishGuard | `upfront_payment` is a **hard block** — it overrides the model score. No legitimate employer or admission asks for money by e-mail |
| **4. Documents requested** | 🪪 ResumeShield | Shows the student exactly which identifiers (Aadhaar, PAN, bank a/c) are sitting in their resume and hands back a safe redacted copy |
| **5. Student checks the "portal"** | 🔐 SiteGuard | Grades the real portal's posture so the genuine site is demonstrably hardened — and misconfigurations aren't the thing that leaks student data |

### 4.3 Concrete value to JMD The Career Maker

**a) It turns "be careful" into a service.**
Today a consultancy's anti-fraud advice is a WhatsApp forward. This suite lets JMD offer
a **"Verify before you pay"** desk: a student pastes the offer or the link, and gets a
verdict with reasons in seconds. That is a differentiator no competing consultancy in the
segment is offering.

**b) It defends the brand, not just the network.**
LinkGuard is configured against JMD's own domain `jmdcareermaker.com`. Every lookalike
scored is an attempt to impersonate JMD specifically. Running it over inbound student
queries gives the firm **early warning of impersonation campaigns** — the firm learns it
is being spoofed from its own students' reports, on day one, instead of from a police
complaint six weeks later.

**c) It makes the firm defensible under the DPDP Act 2023.**
A consultancy holds Aadhaar, PAN, passports, marksheets and bank details for hundreds of
students. ResumeShield produces a **risk band, an inventory, an audit log and a
"safe-to-share" verdict** for every document. When JMD forwards a candidate profile to a
university or employer, it can forward the redacted version and keep the evidence trail.
That converts a legal exposure into a documented process.

**d) It closes the account that scammers most want.**
BreachRadar's scan found `hr@`, `info@` and `careers@` all CRITICAL with passwords
exposed. If any one of those is taken over, the scammer no longer needs a lookalike
domain — they mail students from the **real** address, and every control above is
bypassed. Fixing those accounts is the single highest-leverage action in this report.

**e) It protects the student's money and identity directly.**
The average education-consultancy fraud costs a student a "registration fee" plus a
stolen identity that can be used for loans and SIM fraud for years. PhishGuard's hard
block on payment requests and ResumeShield's redaction attack both halves of that loss.

**f) Every verdict is explainable.**
Every tool returns *named signals with plain-English reasons* — "2 edits from the
official domain", "real destination hidden after an '@'". This matters twice over: a
student learns the pattern and can spot the next scam unaided, and a counsellor can
justify the decision to a parent. A black-box score could not do either.

### 4.4 How JMD would actually deploy it

1. **Public "Scam Check" page** on jmdcareermaker.com — the existing `web/` frontend,
   already built, already deployable with `render.yaml`. Students paste a link or an
   offer letter. Zero training required.
2. **Counsellor console** — the Streamlit console for staff, for bulk checks and for
   ResumeShield redaction before any document leaves the office.
3. **API integration** — the REST API behind the firm's CRM or WhatsApp bot, so every
   inbound student attachment is scanned automatically.
4. **Monthly BreachRadar org scan** as a standing SOC routine.

---

## 5. Honest limitations

- **All datasets are synthetic and seeded.** The ML metrics (LinkGuard held-out accuracy
  0.997) validate that the *pipeline* works; they overstate real-world difficulty because
  the synthetic corpus is separable. Real-world performance requires real data.
- **BreachRadar runs on a local synthetic corpus**, not a live HIBP feed.
- **No email-header authentication yet** — SPF/DKIM/DMARC checks are the obvious next
  layer, and would catch spoofing that body-text analysis cannot.
- **PhishGuard lives in a separate repository** (`~/jmd_phishguard`) and is not bundled
  in the Docker image; the suite degrades gracefully if it is absent.
- **Not yet deployed** to a public URL — `render.yaml` and `DEPLOY.md` are ready but need
  the firm's hosting account.
- **English only** — Hindi/Hinglish scam messages are a real gap for the Indian student
  market.

## 6. Recommended next steps

1. Deploy the website + API to a public URL and link a "Verify Before You Pay" button
   from jmdcareermaker.com.
2. Rotate credentials and enforce MFA on the accounts BreachRadar flagged CRITICAL.
3. Add SPF/DKIM/DMARC header verification to PhishGuard.
4. Add Hindi/Hinglish training data.
5. Wire the 54 tests into CI so every change is verified automatically.

---

**Bottom line.** The suite does not try to secure a network perimeter, because that is
not where an education consultancy is actually attacked. It secures the **trust
relationship between JMD and its students** — the offer letter, the link, the document,
the fee request and the staff mailbox — with five explainable, tested, defence-in-depth
controls behind one console and one API.
