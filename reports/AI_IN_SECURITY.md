# Using AI to Improve Security — System & Organisation

**Author:** Fazal Ahmad — AI Cybersecurity Intern
**Organisation:** JMD The Career Maker
**Companion to:** `TECHNICAL_REPORT.md`

This note explains, **honestly and concretely**, where Artificial Intelligence /
Machine Learning is used in the JMD Security Suite, *why* AI is the right tool for
those problems, and how it strengthens the security posture of the firm as a whole.
It deliberately separates **today's ML**, **AI-shaped automation**, and the
**AI roadmap**, so the claims are credible.

---

## 1. Why AI at all? The threat fits the tool

JMD The Career Maker runs on **language and trust**: recruiter email, offer letters,
candidate resumes, job links and portals. Attacks against a recruitment firm are
therefore mostly *linguistic and pattern-based* — fake offers, lookalike domains,
impersonation, leaked PII. These are exactly the problems where AI/ML outperforms
fixed rules:

| Property of the threat | Why rules alone fall short | What AI adds |
|---|---|---|
| Scam wording constantly varies | A blocklist of phrases is brittle | A model **generalises** to unseen wording |
| Volume of email/resumes/links | Manual review doesn't scale | AI triages **at machine speed**, 24/7 |
| Signals are weak individually | One keyword ≠ fraud | ML **weighs many weak signals** together |
| Analysts need to act, not read | Raw alerts overwhelm a SOC | AI **prioritises + explains** |

The guiding principle across the suite: **AI to decide and prioritise, rules to
guarantee, humans to approve.**

---

## 2. Where AI/ML is used *today*

### 2.1 PhishGuard — supervised ML (the core AI component)
PhishGuard is the suite's genuine machine-learning model: a **TF-IDF + Logistic
Regression** classifier trained to score whether a recruitment message is fraudulent.
- **Learns the language of scams** (urgency, upfront "registration fees", credential
  requests, off-brand sender domains) rather than matching a fixed list.
- **Fused with deterministic rules** that act as *hard-block kill switches* — a model
  can be uncertain, but a demand to pay a fee for a job is blocked regardless.
- Outputs a calibrated fraud probability **plus the red flags behind it**, so the
  decision is explainable to a recruiter, not a black box.

This is **AI-driven threat detection** in the appointment-letter sense: the model
improves as it sees more examples, and the rule layer keeps it safe and auditable.

### 2.2 LinkGuard — supervised ML on URLs (the second AI model)
LinkGuard pairs hand-engineered security heuristics with a **trained
`LogisticRegression` classifier** that learns malicious-vs-benign links from two views:
- **Character n-grams** (`char_wb` TF-IDF) capture the raw *look* of a URL string;
- **Lexical features** from the heuristic engine (typosquat edit-distance, brand
  impersonation, IP host, shortener, suspicious TLD, sub-domain depth …) give the
  model structured security knowledge.

The model returns a calibrated **malicious probability** that is fused as an extra
weighted signal — and is **skipped for the firm's genuine domain**, so a real link is
never penalised. Training data is **synthetic, seeded and offline** (benign links from
real-shaped domains; malicious links built with the actual phishing tricks LinkGuard
targets). On a held-out split it scores **~0.997 accuracy / 1.00 ROC-AUC** — strong, but
honestly that reflects *synthetic, separable* data; the transferable value is the
pipeline (`./run.sh train`, metrics in `linkguard/models/metrics.json`).

### 2.3 AI-shaped automation across the remaining tools
These are **deterministic by design** (reproducible and safe), automating analyst
judgement that would otherwise be manual:
- **ResumeShield** — automated PII discovery with **validation logic** (Aadhaar
  Verhoeff checksum, card Luhn, context-gated bank accounts) to suppress false
  positives, plus an automated DPDP Act 2023 compliance verdict.
- **SiteGuard** — automated, non-intrusive posture assessment and grading.
- **BreachRadar** — automated, **privacy-preserving** k-anonymity exposure lookup
  with multi-factor risk scoring (severity × recency × password × role).

> **Honest framing for the report:** two tools (PhishGuard, LinkGuard) are true
> supervised ML; the others are explainable heuristic/statistical automation. That mix
> is a feature, not a gap — security controls that *guarantee* behaviour should not be
> left to a probabilistic model.

---

## 3. How this improves security *for the organisation*

1. **Defence in depth across the real attack surface.** Email (PhishGuard), links
   (LinkGuard), candidate data (ResumeShield), web posture (SiteGuard) and credentials
   (BreachRadar) are covered by one coordinated suite, not point fixes.
2. **Scale and speed.** AI triages recruitment fraud and risky links the moment they
   arrive, far faster and more consistently than manual review — a force-multiplier for
   a small security team.
3. **A SOC-style single pane of glass.** The unified console + REST API give one
   prioritised view, so analysts spend time on the highest-risk items first.
4. **Explainability builds trust.** Every verdict lists the concrete signals behind it,
   which is what lets non-experts (recruiters, HR) actually act on an alert.
5. **Compliance by design.** Automated DPDP Act 2023 checks and PII redaction reduce
   legal exposure when handling candidate data.
6. **Continuous improvement.** Confirmed scams/links become new training data, so the
   ML layer gets sharper over time — the system *learns* the firm's threat landscape.

---

## 4. Responsible & safe use of AI (governance)

AI in security is only an asset if it is used responsibly:
- **Human-in-the-loop.** AI scores and recommends; it does not take irreversible
  action on its own. High-impact decisions stay with a person.
- **No sensitive data sent to external models.** All analysis here runs **locally and
  offline** — candidate PII is redacted in memory and never persisted or sent to a
  third-party LLM.
- **False-positive control.** Validation checksums, calibrated thresholds and the
  rule/ML split keep legitimate candidates from being wrongly flagged.
- **Explainable, auditable outputs.** Signals, weights and rationale accompany every
  decision, supporting review and accountability.
- **Reproducible & tested.** Seeded data, pinned dependencies and 54 automated tests
  mean behaviour is consistent and verifiable.

---

## 5. AI roadmap — making the system progressively smarter

| Area | Today | Next AI step |
|---|---|---|
| PhishGuard | TF-IDF + LogReg + rules | Transformer embeddings; Hindi/Hinglish coverage; SPF/DKIM/DMARC features |
| ResumeShield | Validated regex + checksums | Fine-tuned **NER** for messy/scanned resumes |
| LinkGuard | **Char-ngram + lexical LogReg** (done) + heuristics | Train on a real reported-phish feed; live URL reputation |
| SiteGuard | Rule-based posture | **Anomaly detection** on header/config baselines |
| BreachRadar | Heuristic risk scoring | Learned risk model on a real breach feed |
| Suite-wide | Per-tool alerts | **Correlation/triage agent** that links signals across tools into one incident |

The long-term vision: an **AI security analyst** for JMD that ingests email, links,
documents and breach signals together, correlates them, and surfaces a single ranked,
explained incident queue — with humans approving the actions.

---

## 6. Conclusion

AI improves security at JMD The Career Maker by doing what fixed rules cannot:
**generalising** to new attacker wording, operating **at scale and speed**, and
**weighing many weak signals** — while staying **explainable, local, and human-governed**.
The suite already proves this with a working ML phishing model plus explainable
automation across the firm's whole attack surface, and has a clear path to a more
fully AI-driven, correlated security operation.
