"""
Generate a synthetic, offline breach corpus for BreachRadar.

No real breach data is used or downloaded — this is a safe, reproducible stand-in
that lets the engine demonstrate exposure lookup, k-anonymity hashing, and risk
scoring without touching any external service.
"""
from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent
SEED = 42
rng = random.Random(SEED)

ORG_DOMAIN = "jmdcareermaker.com"

BREACHES = {
    "CareerPortalLeak2025": {"date": "2025-11-02", "severity": "HIGH",
                             "classes": ["email", "password", "phone"]},
    "JobBoardDump2024":     {"date": "2024-06-20", "severity": "HIGH",
                             "classes": ["email", "password"]},
    "OldForum2019":         {"date": "2019-03-11", "severity": "MEDIUM",
                             "classes": ["email", "username"]},
    "MarketingList2023":    {"date": "2023-09-01", "severity": "LOW",
                             "classes": ["email"]},
    "CloudBucket2022":      {"date": "2022-12-15", "severity": "MEDIUM",
                             "classes": ["email", "password"]},
}

# Org accounts we explicitly want to monitor (high-value: HR / careers / founder).
ORG_EMAILS = [
    f"info@{ORG_DOMAIN}", f"akash.mishra@{ORG_DOMAIN}", f"hr@{ORG_DOMAIN}",
    f"careers@{ORG_DOMAIN}", f"finance@{ORG_DOMAIN}", f"fazal.ahmad@{ORG_DOMAIN}",
    f"neha.gupta@{ORG_DOMAIN}", f"admin@{ORG_DOMAIN}",
]
OTHER_EMAILS = [f"user{n}@example.com" for n in range(1, 60)]


def sha1_hex(s: str) -> str:
    return hashlib.sha1(s.strip().lower().encode()).hexdigest().upper()


def build():
    records = []  # {email, breach, password_exposed}
    pool = ORG_EMAILS + OTHER_EMAILS

    # Seed deterministic exposures, biased so several org accounts are clearly at risk.
    forced = {
        f"akash.mishra@{ORG_DOMAIN}": ["CareerPortalLeak2025", "JobBoardDump2024"],
        f"hr@{ORG_DOMAIN}": ["CareerPortalLeak2025"],
        f"careers@{ORG_DOMAIN}": ["MarketingList2023", "OldForum2019"],
        f"info@{ORG_DOMAIN}": ["CloudBucket2022"],
    }
    for email, brs in forced.items():
        for b in brs:
            records.append({"email": email, "breach": b,
                            "password_exposed": "password" in BREACHES[b]["classes"]})

    for email in pool:
        for b in BREACHES:
            if rng.random() < 0.12:
                records.append({"email": email, "breach": b,
                                "password_exposed": "password" in BREACHES[b]["classes"]
                                and rng.random() < 0.7})

    # k-anonymity index: sha1(email) -> list of {breach, password_exposed}
    index = {}
    for r in records:
        h = sha1_hex(r["email"])
        index.setdefault(h, []).append({"breach": r["breach"],
                                        "password_exposed": r["password_exposed"]})

    out = {"breaches": BREACHES, "org_domain": ORG_DOMAIN,
           "org_emails": ORG_EMAILS, "hash_index": index}
    (HERE / "breach_corpus.json").write_text(json.dumps(out, indent=2))
    print(f"Breaches: {len(BREACHES)} | leaked records: {len(records)} | "
          f"hashed accounts: {len(index)}")
    print(f"Wrote -> {HERE / 'breach_corpus.json'}")


if __name__ == "__main__":
    build()
