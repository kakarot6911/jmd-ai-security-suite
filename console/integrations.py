"""
Unified adapter over all four tools, so the console UI and the REST API share one
import surface. Handles the cross-project path to PhishGuard.
"""
from __future__ import annotations

import functools
import sys
from pathlib import Path

SUITE_ROOT = Path(__file__).resolve().parents[1]
PHISHGUARD_ROOT = Path("/Users/fazalahmad/jmd_phishguard")

for p in (str(SUITE_ROOT), str(PHISHGUARD_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

# Suite tools
from resumeshield.redact import redact as _redact          # noqa: E402
from siteguard.scanner import scan as _scan                # noqa: E402
from siteguard.demo import DEMOS as SITEGUARD_DEMOS        # noqa: E402
from breachradar.engine import BreachRadar                 # noqa: E402

PHISHGUARD_AVAILABLE = (PHISHGUARD_ROOT / "models" / "phishguard_model.joblib").exists()


@functools.lru_cache(maxsize=1)
def _radar() -> BreachRadar:
    return BreachRadar()


@functools.lru_cache(maxsize=1)
def _phish():
    """Lazily import PhishGuard so the suite works even if it isn't present."""
    from src.predict import analyze  # noqa: E402  (PhishGuard's package)
    return analyze


# --- Uniform callables -----------------------------------------------------
def phishguard_analyze(text: str, sender_email: str = "", claimed_company: str = "") -> dict:
    if not PHISHGUARD_AVAILABLE:
        raise RuntimeError("PhishGuard model not found (~/jmd_phishguard). Train it first.")
    return _phish()(text, sender_email, claimed_company).to_dict()


def resumeshield_redact(text: str, keep_last: int = 0) -> dict:
    r = _redact(text, keep_last=keep_last)
    return {
        "risk_score": r.risk_score, "risk_band": r.risk_band, "inventory": r.inventory,
        "redacted_text": r.redacted_text, "dpdp": r.dpdp,
        "matches": [{"type": m.type, "sensitivity": m.sensitivity} for m in r.matches],
    }


def siteguard_scan(url: str, authorized: bool = False, demo: str | None = None) -> dict:
    if demo:
        return _scan(f"https://{demo}.demo", authorized=True,
                     fetcher=SITEGUARD_DEMOS[demo]).to_dict()
    return _scan(url, authorized=authorized).to_dict()


def breachradar_check(email: str) -> dict:
    return _radar().check(email).to_dict()


def breachradar_scan_org() -> list[dict]:
    radar = _radar()
    return [x.to_dict() for x in radar.scan(radar.org_emails)]


def org_emails() -> list[str]:
    return _radar().org_emails


TOOLS = [
    {"key": "phishguard", "icon": "🛡️", "name": "PhishGuard",
     "desc": "Detects fake job offers, recruitment scams & phishing impersonating the firm.",
     "available": PHISHGUARD_AVAILABLE},
    {"key": "resumeshield", "icon": "🪪", "name": "ResumeShield",
     "desc": "Redacts candidate PII and reports DPDP Act 2023 compliance before sharing resumes.",
     "available": True},
    {"key": "siteguard", "icon": "🔐", "name": "SiteGuard",
     "desc": "Passive web security-posture scanner for the firm's site & candidate portal.",
     "available": True},
    {"key": "breachradar", "icon": "📡", "name": "BreachRadar",
     "desc": "Monitors staff/recruiter accounts for exposure in known data breaches.",
     "available": True},
]
