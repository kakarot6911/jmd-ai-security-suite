"""
Held-out generalisation check.

The cases in cases.py were used to *drive* the accuracy fixes, so scoring 100%
on them proves only that the fixes did what they were aimed at. These cases were
written afterwards and run once, without tuning anything in response — they are
the honest estimate of whether the improvements generalise.

Run:  python eval/holdout.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path.home() / "jmd_phishguard"))

# --- LinkGuard: (url, should_flag) ------------------------------------------
LINKS = [
    ("https://jmdcareer-maker.com/apply", True),            # hyphen-inserted lookalike
    ("https://jmdcareermaker.support/login", True),          # brand + abused TLD
    ("http://tinyurl.com/y8kx2p", True),                     # different shortener
    ("https://jmdcareermakerr.com/", True),                  # doubled final letter
    ("https://careers.jmdcareermaker.com.cn-verify.gq/pay", True),
    ("vbscript:msgbox(1)", True),                            # another pseudo-scheme
    ("https://drive.google.com/file/d/1a2b3c/view", False),   # real file share
    ("https://www.jmdcareermaker.com/contact-us", False),     # official
    ("https://stackoverflow.com/questions/12345", False),
    ("https://www.hdfcbank.com/personal/pay/money-transfer", False),   # 'pay' on a real bank
    ("https://en.wikipedia.org/wiki/Secure_Shell", False),    # 'secure' in a real article
    ("https://unstop.com/internships/cybersecurity-intern", False),
]

# --- ResumeShield: (text, must_find, must_not_find) -------------------------
RESUMES = [
    ("Contact: 9876543210 | rahul.sharma@gmail.com", {"PHONE", "EMAIL"}, set()),
    ("PAN No. BXYPS9012K issued 2019", {"PAN"}, set()),
    ("Achieved revenue of 850000 in FY22", set(), {"PIN_CODE"}),
    ("Handled 120000 support tickets", set(), {"PIN_CODE"}),
    ("Residence: 14 MG Road, Bengaluru 560001", {"PIN_CODE"}, set()),
    ("Passport No: L4567890 valid till 2030", {"PASSPORT"}, set()),
    ("Certification ID: C9876543 from AWS", set(), {"PASSPORT"}),
    ("Salary account IFSC ICIC0001234", {"IFSC"}, set()),
    ("Roll number 202100456789 at university", set(), {"UAN"}),
]

# --- PhishGuard: (text, sender, company, is_scam) ---------------------------
MESSAGES = [
    ("Selected for immediate joining! Send Rs 999 as document verification charge "
     "to activate your offer letter today.", "jobs.jmd@gmail.com", "JMD The Career Maker", True),
    ("Share your debit card number and OTP so we can credit your joining bonus.",
     "payroll@jmd-verify.tk", "JMD The Career Maker", True),
    ("Work from home data entry. Earn 3000 daily. No interview required. "
     "Message on Telegram to start.", "hiring2026@yahoo.com", "JMD The Career Maker", True),
    ("Hi Ananya, your application for the Data Analyst role has moved to the technical "
     "round. Please pick a slot using the scheduling link in your dashboard.",
     "talent@jmdcareermaker.com", "JMD The Career Maker", False),
    ("Following our discussion, the revised CTC is Rs 15 LPA with a 10% variable "
     "component. Let me know if you would like to proceed.",
     "hr@jmdcareermaker.com", "JMD The Career Maker", False),
    ("Reminder: your onboarding documents are due before Friday. Upload them to the "
     "HR portal at your convenience.", "onboarding@jmdcareermaker.com",
     "JMD The Career Maker", False),
    ("We are hiring backend engineers at my startup. Salary is competitive. "
     "Let me know if you'd like details.", "arjun@gmail.com", "", False),
]


def main() -> int:
    from linkguard.engine import analyze_url
    from resumeshield.pii import detect

    total = correct = 0
    misses = []

    for url, should in LINKS:
        total += 1
        try:
            got = analyze_url(url).verdict in {"SUSPICIOUS", "DANGEROUS"}
        except Exception as e:  # noqa: BLE001
            misses.append(f"LinkGuard CRASH  {url}  {type(e).__name__}: {e}")
            continue
        if got == should:
            correct += 1
        else:
            misses.append(f"LinkGuard  {'FP' if got else 'FN'}  {url}")

    for text, must, must_not in RESUMES:
        found = {m.type for m in detect(text)}
        for t in must:
            total += 1
            if t in found:
                correct += 1
            else:
                misses.append(f"ResumeShield FN  {t} missing in {text[:44]!r}")
        for t in must_not:
            total += 1
            if t not in found:
                correct += 1
            else:
                misses.append(f"ResumeShield FP  {t} wrongly found in {text[:44]!r}")

    try:
        from src.predict import analyze
        for text, sender, company, is_scam in MESSAGES:
            total += 1
            p = analyze(text, sender, company).fraud_probability
            if (p >= 0.5) == is_scam:
                correct += 1
            else:
                misses.append(f"PhishGuard {'FP' if p >= 0.5 else 'FN'}  p={p:.2f}  {text[:52]!r}")
    except Exception as e:  # noqa: BLE001
        print(f"! PhishGuard unavailable ({e}) — skipped")

    print("=" * 74)
    print("HELD-OUT generalisation check (never tuned against)")
    print("=" * 74)
    for m in misses:
        print(f"  · {m}")
    print(f"\n{correct}/{total} correct = {correct / total:.1%}"
          f"   ({len(misses)} miss{'es' if len(misses) != 1 else ''})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
