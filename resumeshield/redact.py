"""Redaction, risk scoring, and DPDP Act 2023 compliance reporting."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List

from .pii import Match, SENSITIVITY, detect, inventory

# Which detected types count as "sensitive personal data" under DPDP guidance.
SENSITIVE_TYPES = {"AADHAAR", "PAN", "PASSPORT", "GSTIN", "BANK_ACCOUNT", "CREDIT_CARD"}

ORG_NAME = "JMD The Career Maker"


@dataclass
class RedactionResult:
    original_len: int
    redacted_text: str
    matches: List[Match]
    risk_score: int                       # 0-100
    risk_band: str
    inventory: Dict[str, int]
    audit_log: List[dict] = field(default_factory=list)
    dpdp: dict = field(default_factory=dict)


def _mask(m: Match, keep_last: int = 0) -> str:
    if keep_last and len(m.value) > keep_last:
        return f"[{m.type}:••••{m.value[-keep_last:]}]"
    return f"[REDACTED:{m.type}]"


def redact(text: str, keep_last: int = 0) -> RedactionResult:
    text = text or ""
    matches = detect(text)

    # Rebuild the string left-to-right, replacing each (non-overlapping) span.
    out, cursor, audit = [], 0, []
    for m in matches:
        out.append(text[cursor:m.start])
        out.append(_mask(m, keep_last))
        cursor = m.end
        audit.append({
            "type": m.type, "sensitivity": m.sensitivity,
            "confidence": round(m.confidence, 2),
            "span": [m.start, m.end],
        })
    out.append(text[cursor:])
    redacted = "".join(out)

    score = _risk_score(matches)
    band = ("CRITICAL" if score >= 75 else "HIGH" if score >= 50
            else "MEDIUM" if score >= 25 else "LOW")

    return RedactionResult(
        original_len=len(text),
        redacted_text=redacted,
        matches=matches,
        risk_score=score,
        risk_band=band,
        inventory=inventory(matches),
        audit_log=audit,
        dpdp=dpdp_report(matches, score, band),
    )


def _risk_score(matches: List[Match]) -> int:
    if not matches:
        return 0
    raw = sum(m.weight for m in matches)
    # squashing so a handful of high-sensitivity items already lands high
    score = 100 * (1 - 1 / (1 + raw))
    return int(round(min(score, 100)))


def dpdp_report(matches: List[Match], score: int, band: str) -> dict:
    found_sensitive = sorted({m.type for m in matches if m.type in SENSITIVE_TYPES})
    classes = sorted({m.sensitivity for m in matches})
    obligations = [
        "Process candidate personal data only for the stated recruitment purpose (purpose limitation).",
        "Obtain and record the candidate's consent before sharing data with employer clients.",
        "Mask/redact Government IDs and financial data before forwarding a resume to any third party.",
        "Apply reasonable security safeguards and retain data only as long as necessary.",
        "Honour candidate rights to access, correction, and erasure of their data.",
    ]
    return {
        "regulation": "Digital Personal Data Protection Act, 2023 (India)",
        "data_fiduciary": ORG_NAME,
        "assessed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "personal_data_classes_present": classes,
        "sensitive_identifiers_present": found_sensitive,
        "exposure_risk_score": score,
        "exposure_risk_band": band,
        "compliant_to_share_as_is": len(found_sensitive) == 0 and score < 25,
        "required_actions": (
            ["Redact the sensitive identifiers above before sharing."] if found_sensitive
            else ["Low residual risk; standard handling applies."]
        ),
        "standing_obligations": obligations,
    }


if __name__ == "__main__":
    sample = (
        "Name: Fazal Ahmad\nEmail: fazal.ahmad@example.com  Phone: +91 98765 43210\n"
        "Aadhaar: 2994 1855 6015   PAN: ABCDE1234F\nA/c 123456789012 at HDFC.\n"
        "DOB: 23/08/2001  Address: Tower 28, Lodha Belmondo, Pune 411045"
    )
    r = redact(sample, keep_last=4)
    print("RISK:", r.risk_score, r.risk_band)
    print("INVENTORY:", r.inventory)
    print("--- redacted ---")
    print(r.redacted_text)
    print("COMPLIANT TO SHARE AS-IS:", r.dpdp["compliant_to_share_as_is"])
