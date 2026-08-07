"""
BreachRadar core — privacy-preserving credential-exposure lookup + risk scoring.

Lookups use a k-anonymity hash-prefix model (the same idea as HIBP's range API):
the caller's email is SHA-1 hashed, and only a 5-char prefix is used to fetch a
bucket of candidate hashes; the full hash is matched locally. This means a real
deployment could query a remote store without ever revealing which address it is
checking. Here the store is a local, synthetic corpus (offline & safe).
"""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Dict, List

CORPUS_PATH = Path(__file__).resolve().parent / "data" / "breach_corpus.json"

SEVERITY_WEIGHT = {"HIGH": 40, "MEDIUM": 20, "LOW": 10}
HIGH_VALUE_LOCALPARTS = {"hr", "careers", "admin", "finance", "ceo", "founder",
                         "info", "payroll", "accounts", "recruitment"}


@dataclass
class Exposure:
    email: str
    breaches: List[dict] = field(default_factory=list)   # {breach,date,severity,classes,password_exposed}
    password_exposed: bool = False
    high_value_target: bool = False
    risk_score: int = 0
    risk_band: str = "NONE"
    advice: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "email": self.email, "exposed": bool(self.breaches),
            "breach_count": len(self.breaches), "password_exposed": self.password_exposed,
            "high_value_target": self.high_value_target, "risk_score": self.risk_score,
            "risk_band": self.risk_band, "breaches": self.breaches, "advice": self.advice,
        }


def sha1_hex(s: str) -> str:
    return hashlib.sha1(s.strip().lower().encode()).hexdigest().upper()


class BreachRadar:
    def __init__(self, corpus_path: Path = CORPUS_PATH):
        if not corpus_path.exists():
            raise FileNotFoundError(
                f"Corpus missing: {corpus_path}\nRun: python breachradar/data/generate_breaches.py")
        data = json.loads(corpus_path.read_text())
        self.breaches: Dict[str, dict] = data["breaches"]
        self.index: Dict[str, list] = data["hash_index"]
        self.org_domain: str = data.get("org_domain", "")
        self.org_emails: List[str] = data.get("org_emails", [])

    # --- k-anonymity lookup -------------------------------------------------
    def range_query(self, prefix: str) -> Dict[str, list]:
        """Return all {hash_suffix: breaches} whose SHA-1 starts with `prefix`."""
        prefix = prefix.upper()
        return {h[len(prefix):]: v for h, v in self.index.items() if h.startswith(prefix)}

    def _lookup(self, email: str) -> List[dict]:
        full = sha1_hex(email)
        bucket = self.range_query(full[:5])          # only the prefix would leave the client
        return bucket.get(full[5:], [])

    # --- scoring ------------------------------------------------------------
    def check(self, email: str, today: date | None = None) -> Exposure:
        today = today or date.today()
        hits = self._lookup(email)
        local = email.strip().lower().split("@")[0]
        high_value = local in HIGH_VALUE_LOCALPARTS

        # The same account can appear more than once for a breach (multiple dumps of
        # the same incident). Collapse by breach name first — counting an incident
        # twice inflates the score and makes accounts saturate at 100, which destroys
        # the ranking the org-wide scan depends on. Keep the worst variant of each.
        by_name: Dict[str, dict] = {}
        for h in hits:
            name = h.get("breach", "")
            prev = by_name.get(name)
            if prev is None or (h.get("password_exposed") and not prev.get("password_exposed")):
                by_name[name] = h
        unique_hits = list(by_name.values())

        enriched, raw_score, pwd = [], 0.0, False
        for h in unique_hits:
            meta = self.breaches.get(h["breach"], {})
            sev = meta.get("severity", "LOW")
            bdate = meta.get("date", "2000-01-01")
            years = max(0.0, (today - datetime.strptime(bdate, "%Y-%m-%d").date()).days / 365.0)
            recency = 1.0 if years <= 1 else 0.7 if years <= 3 else 0.4
            contrib = SEVERITY_WEIGHT.get(sev, 10) * recency
            if h.get("password_exposed"):
                contrib += 25
                pwd = True
            raw_score += contrib
            enriched.append({"breach": h["breach"], "date": bdate, "severity": sev,
                             "classes": meta.get("classes", []),
                             "password_exposed": h.get("password_exposed", False)})

        if high_value and unique_hits:
            raw_score += 15

        # Compress with diminishing returns instead of a hard clamp. A hard min(x,100)
        # made every badly-exposed account tie at exactly 100; this keeps the 0-100
        # range while preserving the ordering between them.
        score = int(round(100 * (1 - math.exp(-raw_score / 70.0)))) if raw_score > 0 else 0
        band = ("CRITICAL" if score >= 70 else "HIGH" if score >= 45
                else "MEDIUM" if score >= 20 else "LOW" if score > 0 else "NONE")

        return Exposure(
            email=email, breaches=sorted(enriched, key=lambda x: x["date"], reverse=True),
            password_exposed=pwd, high_value_target=high_value,
            risk_score=score, risk_band=band, advice=self._advice(pwd, high_value, enriched),
        )

    @staticmethod
    def _advice(pwd: bool, high_value: bool, breaches: list) -> List[str]:
        if not breaches:
            return ["No known exposure. Maintain MFA and routine password hygiene."]
        a = ["Force a password reset for this account."]
        if pwd:
            a.append("Password was exposed — rotate it everywhere it was reused and enable MFA.")
        if high_value:
            a.append("High-value role (HR/finance/admin) — prioritise and monitor for phishing.")
        a.append("Enable multi-factor authentication and check login history.")
        return a

    def scan(self, emails: List[str]) -> List[Exposure]:
        return sorted((self.check(e) for e in emails),
                      key=lambda x: x.risk_score, reverse=True)


if __name__ == "__main__":
    radar = BreachRadar()
    for e in radar.org_emails[:5]:
        x = radar.check(e)
        print(f"{e:34} {x.risk_band:8} score={x.risk_score:3}  "
              f"breaches={len(x.breaches)}  pwd={x.password_exposed}")
