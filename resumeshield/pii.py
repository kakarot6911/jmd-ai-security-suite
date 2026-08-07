"""
PII detection engine for candidate resumes (India-aware).

Each detector returns Match objects with character spans, a confidence, and a
DPDP sensitivity class. Detectors are deterministic and explainable — important
for a compliance tool where every redaction must be auditable.

Validation (Aadhaar Verhoeff checksum, credit-card Luhn) is used to keep
false positives low so we don't redact ordinary numbers.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

# DPDP sensitivity classes (drives risk weight & the compliance report)
SENSITIVITY = {
    "GOVERNMENT_ID": 1.0,     # Aadhaar, PAN, Passport, GSTIN
    "FINANCIAL": 1.0,         # bank account, card
    "CONTACT": 0.5,           # email, phone
    "IDENTITY": 0.6,          # name, DOB
    "LOCATION": 0.5,          # address / PIN
    "ONLINE": 0.3,            # personal URLs
}


@dataclass
class Match:
    type: str
    value: str
    start: int
    end: int
    confidence: float
    sensitivity: str

    @property
    def weight(self) -> float:
        return SENSITIVITY.get(self.sensitivity, 0.4) * self.confidence


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------
def luhn_ok(num: str) -> bool:
    digits = [int(d) for d in num if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# Verhoeff checksum (used by Aadhaar)
_D = [
    [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
    [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
    [9,8,7,6,5,4,3,2,1,0],
]
_P = [
    [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
    [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
    [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8],
]


def verhoeff_ok(num: str) -> bool:
    digits = [int(d) for d in num if d.isdigit()]
    if len(digits) != 12:
        return False
    c = 0
    for i, d in enumerate(reversed(digits)):
        c = _D[c][_P[i % 8][d]]
    return c == 0


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\-\s]?)?[6-9]\d{4}[\-\s]?\d{5}(?!\d)")
AADHAAR_RE = re.compile(r"(?<!\d)\d{4}\s?\d{4}\s?\d{4}(?!\d)")
PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
GSTIN_RE = re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][0-9A-Z]Z[0-9A-Z]\b")
CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,16}(?!\d)")

# A bare 6-digit number is far more often a salary, a score or a headcount than a
# postal code. Requiring address context is the single biggest false-positive
# reduction in this module, so PIN codes are only accepted when they follow an
# explicit PIN label or trail an address-like phrase.
PIN_LABELLED_RE = re.compile(
    r"\b(?:PIN|PIN\s?code|Pincode|Postal\s?code|Zip)\b[\s:\-]*(?<!\d)([1-9]\d{5})(?!\d)", re.I)
PIN_AFTER_PLACE_RE = re.compile(
    r"(?:Address|Addr|Street|Road|Lane|Nagar|Colony|Sector|City|State|"
    r"Mumbai|Pune|Delhi|Bengaluru|Bangalore|Chennai|Kolkata|Hyderabad|Ahmedabad|"
    r"Jaipur|Lucknow|Noida|Gurgaon|Gurugram|Thane|Nashik|Indore|Bhopal)"
    r"[^\n]{0,60}?(?<!\d)([1-9]\d{5})(?!\d)", re.I)

# Passport numbers look like many ordinary reference codes, so require the word.
PASSPORT_CTX_RE = re.compile(
    r"\bpassport\b(?:\s*(?:no|number|#))?[\s:\-]*\b([A-PR-WYa-prwy][0-9]{7})\b", re.I)

# --- additional Indian identifiers commonly present on real resumes ---------
IFSC_RE = re.compile(r"\b([A-Z]{4}0[A-Z0-9]{6})\b")
UAN_RE = re.compile(r"\b(?:UAN|Universal\s+Account\s+(?:No|Number))\b[\s:\-]*(?<!\d)(\d{12})(?!\d)", re.I)
VOTER_ID_RE = re.compile(
    r"\b(?:Voter\s*(?:ID|Id)?|EPIC)\b(?:\s*(?:no|number|#))?[\s:\-]*\b([A-Z]{3}\d{7})\b", re.I)
UPI_ID_RE = re.compile(
    r"\b([A-Za-z0-9.\-_]{2,50}@(?:okhdfcbank|okicici|oksbi|okaxis|ybl|paytm|apl|"
    r"axl|ibl|upi|hdfcbank|icici|sbi|axisbank|kotak|freecharge))\b", re.I)
DRIVING_LICENCE_RE = re.compile(
    r"\b(?:DL|Driving\s+Licen[cs]e)\b(?:\s*(?:no|number|#))?[\s:\-]*"
    r"([A-Z]{2}[\s\-]?\d{2}[\s\-]?(?:19|20)?\d{2}[\s\-]?\d{6,7})\b", re.I)
URL_RE = re.compile(r"https?://(?:www\.)?(?:linkedin\.com|github\.com|instagram\.com|facebook\.com)/\S+", re.I)
DOB_RE = re.compile(
    r"\b(?:DOB|D\.O\.B\.?|date of birth)\b[:\s]*"
    r"(\d{1,2}[\-/]\d{1,2}[\-/]\d{2,4}|\d{1,2}\s+\w+\s+\d{4})", re.I)
NAME_RE = re.compile(r"\b(?:Name|Candidate|Full Name)\b[ \t:]+([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){1,2})")
ACCT_CTX_RE = re.compile(
    r"\b(?:a/?c|account)\b[^\d]{0,20}(\d{9,18})", re.I)


def _find(regex, text, type_, sensitivity, conf, group=0):
    out = []
    for m in regex.finditer(text):
        out.append(Match(type_, m.group(group), m.start(group), m.end(group), conf, sensitivity))
    return out


def detect(text: str) -> List[Match]:
    text = text or ""
    matches: List[Match] = []

    matches += _find(EMAIL_RE, text, "EMAIL", "CONTACT", 0.97)
    matches += _find(PHONE_RE, text, "PHONE", "CONTACT", 0.9)
    matches += _find(PAN_RE, text, "PAN", "GOVERNMENT_ID", 0.95)
    matches += _find(GSTIN_RE, text, "GSTIN", "GOVERNMENT_ID", 0.95)
    matches += _find(URL_RE, text, "PERSONAL_URL", "ONLINE", 0.8)
    matches += _find(NAME_RE, text, "NAME", "IDENTITY", 0.85, group=1)
    matches += _find(DOB_RE, text, "DOB", "IDENTITY", 0.9, group=1)

    # Context-gated detectors — these patterns are too generic to trust unlabelled.
    matches += _find(PASSPORT_CTX_RE, text, "PASSPORT", "GOVERNMENT_ID", 0.9, group=1)
    matches += _find(PIN_LABELLED_RE, text, "PIN_CODE", "LOCATION", 0.9, group=1)
    matches += _find(PIN_AFTER_PLACE_RE, text, "PIN_CODE", "LOCATION", 0.75, group=1)

    # Additional Indian identifiers seen on real resumes (all DPDP-relevant).
    matches += _find(IFSC_RE, text, "IFSC", "FINANCIAL", 0.9, group=1)
    matches += _find(UAN_RE, text, "UAN", "GOVERNMENT_ID", 0.9, group=1)
    matches += _find(VOTER_ID_RE, text, "VOTER_ID", "GOVERNMENT_ID", 0.9, group=1)
    matches += _find(UPI_ID_RE, text, "UPI_ID", "FINANCIAL", 0.85, group=1)
    matches += _find(DRIVING_LICENCE_RE, text, "DRIVING_LICENCE", "GOVERNMENT_ID", 0.85, group=1)

    # Aadhaar: only accept Verhoeff-valid 12-digit groups.
    for m in AADHAAR_RE.finditer(text):
        digits = re.sub(r"\s", "", m.group())
        if verhoeff_ok(digits):
            matches.append(Match("AADHAAR", m.group(), m.start(), m.end(), 0.98, "GOVERNMENT_ID"))

    # Cards: only Luhn-valid.
    for m in CARD_RE.finditer(text):
        if luhn_ok(m.group()):
            matches.append(Match("CREDIT_CARD", m.group(), m.start(), m.end(), 0.9, "FINANCIAL"))

    # Bank account: require an account-context keyword to avoid eating any long number.
    for m in ACCT_CTX_RE.finditer(text):
        matches.append(Match("BANK_ACCOUNT", m.group(1), m.start(1), m.end(1), 0.85, "FINANCIAL"))

    return _resolve_overlaps(matches)


def _resolve_overlaps(matches: List[Match]) -> List[Match]:
    """Keep highest-weight match when spans overlap; return sorted by start."""
    chosen: List[Match] = []
    for m in sorted(matches, key=lambda x: (-x.weight, x.start)):
        if any(not (m.end <= c.start or m.start >= c.end) for c in chosen):
            continue
        chosen.append(m)
    return sorted(chosen, key=lambda x: x.start)


def inventory(matches: List[Match]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for m in matches:
        out[m.type] = out.get(m.type, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))
