"""
BreachRadar live feeds — REAL breach data from Have I Been Pwned.

Everything the rest of the suite does runs on a local synthetic corpus so demos
and tests are deterministic and offline. This module is the opt-in bridge to
real-world data, using only the two HIBP endpoints that are free and keyless:

  * Pwned Passwords range  — https://api.pwnedpasswords.com/range/{prefix5}
    k-anonymity: only the first 5 chars of the SHA-1 leave the caller, so the
    password itself is never transmitted or derivable from the request.
  * Breach catalogue       — https://haveibeenpwned.com/api/v3/breaches
    the real, public register of ~1000 verified breaches (names, dates, counts,
    data classes). No key, no personal data involved.

The per-account lookup (email -> breaches) is a PAID HIBP endpoint; it is
supported but only activates when HIBP_API_KEY is set in the environment.

Design rules that keep this safe to call from a web request:
  * every call is time-bounded and retried at most once
  * the catalogue is cached on disk with a TTL, so normal use hits no network
  * failures raise LiveDataUnavailable — never a bare requests exception — so
    callers can fall back to the synthetic corpus with a clear message
  * nothing here runs at import time
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional

CACHE_PATH = Path(__file__).resolve().parent / "data" / "hibp_catalogue.json"
CACHE_TTL_SECONDS = 24 * 60 * 60          # the register changes a few times a month

RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
CATALOGUE_URL = "https://haveibeenpwned.com/api/v3/breaches"
ACCOUNT_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"

# HIBP asks every consumer to identify itself; requests without a UA are rejected.
USER_AGENT = "JMD-Security-Suite (github.com/kakarot6911/jmd-ai-security-suite)"
TIMEOUT_SECONDS = 10.0

# Real HIBP data classes, graded by what an attacker can actually do with them.
# Anything not listed is treated as LOW.
HIGH_IMPACT_CLASSES = {
    "Passwords", "Partial credit card data", "Credit cards", "Bank account numbers",
    "Government issued IDs", "Social security numbers", "Passport numbers",
    "Auth tokens", "Security questions and answers", "Private messages",
    "Biometric data", "Credit card CVV", "Encrypted keys", "Historical passwords",
    "PINs", "Tax records",
}
MEDIUM_IMPACT_CLASSES = {
    "Email addresses", "Phone numbers", "Physical addresses", "Dates of birth",
    "Employers", "Job titles", "Geographic locations", "IP addresses",
    "Names", "Genders", "Usernames",
}


class LiveDataUnavailable(RuntimeError):
    """Raised when real data could not be fetched. Callers should degrade gracefully."""


@dataclass
class PasswordExposure:
    """Result of a real Pwned Passwords k-anonymity check."""
    times_seen: int = 0
    prefix_sent: str = ""
    candidates_returned: int = 0
    source: str = "hibp-pwned-passwords"

    @property
    def compromised(self) -> bool:
        return self.times_seen > 0

    def to_dict(self) -> dict:
        return {
            "compromised": self.compromised,
            "times_seen": self.times_seen,
            "prefix_sent": self.prefix_sent,
            "candidates_returned": self.candidates_returned,
            "severity": severity_for_count(self.times_seen),
            "advice": password_advice(self.times_seen),
            "source": self.source,
        }


def severity_for_count(times_seen: int) -> str:
    """Grade a password by how widely it is already known to attackers."""
    if times_seen == 0:
        return "NONE"
    if times_seen >= 100_000:
        return "CRITICAL"
    if times_seen >= 1_000:
        return "HIGH"
    if times_seen >= 10:
        return "MEDIUM"
    return "LOW"


def password_advice(times_seen: int) -> List[str]:
    if times_seen == 0:
        return [
            "This password does not appear in any known breach corpus.",
            "Absence is not proof of strength — still use a long unique passphrase and MFA.",
        ]
    return [
        f"Seen {times_seen:,} times in real breach data — treat it as public.",
        "Stop using it immediately, everywhere it was reused.",
        "Replace it with a unique passphrase from a password manager and enable MFA.",
    ]


def classes_to_severity(data_classes: List[str]) -> str:
    """Map a real HIBP DataClasses list onto the suite's HIGH/MEDIUM/LOW scale."""
    classes = set(data_classes or [])
    if classes & HIGH_IMPACT_CLASSES:
        return "HIGH"
    if classes & MEDIUM_IMPACT_CLASSES:
        return "MEDIUM"
    return "LOW"


def _default_fetcher(url: str, headers: Dict[str, str]) -> tuple[int, str]:
    """Single HTTP GET. Isolated so tests can inject a fake with no network."""
    import requests  # imported lazily so the module stays import-safe offline

    r = requests.get(url, headers=headers, timeout=TIMEOUT_SECONDS)
    return r.status_code, r.text


class HibpClient:
    """
    Thin, defensive client over the free HIBP endpoints.

    `fetcher` is injectable: it takes (url, headers) and returns (status, text).
    Tests pass a stub, so the suite's test run never touches the network.
    """

    def __init__(
        self,
        fetcher: Optional[Callable[[str, Dict[str, str]], tuple[int, str]]] = None,
        api_key: Optional[str] = None,
        cache_path: Path = CACHE_PATH,
        now: Optional[Callable[[], float]] = None,
    ):
        self._fetch = fetcher or _default_fetcher
        self.api_key = api_key if api_key is not None else os.environ.get("HIBP_API_KEY", "")
        self.cache_path = Path(cache_path)
        self._now = now or time.time

    # --- transport ---------------------------------------------------------
    def _get(self, url: str, extra_headers: Optional[Dict[str, str]] = None) -> tuple[int, str]:
        """GET with one retry. Any transport error becomes LiveDataUnavailable."""
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if extra_headers:
            headers.update(extra_headers)

        last_error = ""
        for attempt in (1, 2):
            try:
                status, text = self._fetch(url, headers)
            except Exception as e:                      # noqa: BLE001 — deliberately broad
                last_error = f"{type(e).__name__}: {e}"
                if attempt == 2:
                    break
                continue
            if status == 200 or status == 404:          # 404 is a valid "not found" answer
                return status, text
            if status == 429 and attempt == 1:
                continue                                # HIBP throttles; one retry is polite
            last_error = f"HTTP {status}"
            if attempt == 2:
                break
        raise LiveDataUnavailable(f"HIBP request failed ({last_error}): {url}")

    # --- 1. real password exposure (free, keyless, k-anonymous) ------------
    def password_exposure_by_prefix(self, prefix: str, suffix: str) -> PasswordExposure:
        """
        Check a SHA-1 that was split by the CALLER.

        Only `prefix` (5 hex chars) is sent upstream; `suffix` is matched locally
        and never transmitted. This is the whole point of the k-anonymity model —
        neither HIBP nor this server learns which password was checked.
        """
        prefix = (prefix or "").strip().upper()
        suffix = (suffix or "").strip().upper()
        if len(prefix) != 5 or not all(c in "0123456789ABCDEF" for c in prefix):
            raise ValueError("prefix must be exactly 5 hexadecimal characters")

        _, text = self._get(RANGE_URL.format(prefix=prefix))
        count, returned = 0, 0
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            returned += 1
            got_suffix, _, got_count = line.partition(":")
            if suffix and got_suffix.upper() == suffix:
                try:
                    count = int(got_count.replace(",", ""))
                except ValueError:
                    count = 0
        return PasswordExposure(times_seen=count, prefix_sent=prefix, candidates_returned=returned)

    def range_raw(self, prefix: str) -> str:
        """Return the raw HIBP range body so a browser can do the matching itself."""
        prefix = (prefix or "").strip().upper()
        if len(prefix) != 5 or not all(c in "0123456789ABCDEF" for c in prefix):
            raise ValueError("prefix must be exactly 5 hexadecimal characters")
        _, text = self._get(RANGE_URL.format(prefix=prefix))
        return text

    # --- 2. real breach catalogue (free, keyless, cached) -----------------
    def _cache_read(self) -> Optional[List[dict]]:
        try:
            blob = json.loads(self.cache_path.read_text())
            if self._now() - float(blob.get("fetched_at", 0)) > CACHE_TTL_SECONDS:
                return None
            data = blob.get("breaches")
            return data if isinstance(data, list) and data else None
        except Exception:                               # noqa: BLE001 — a bad cache is just a miss
            return None

    def _cache_write(self, breaches: List[dict]) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(
                {"fetched_at": self._now(), "source": CATALOGUE_URL, "breaches": breaches}))
        except Exception:                               # noqa: BLE001 — cache is an optimisation
            pass

    def catalogue(self, refresh: bool = False) -> List[dict]:
        """
        The real, public HIBP breach register — normalised to the suite's schema.

        Served from a 24h disk cache, so repeated calls do no network I/O.
        """
        if not refresh:
            cached = self._cache_read()
            if cached is not None:
                return cached

        _, text = self._get(CATALOGUE_URL)
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as e:
            raise LiveDataUnavailable(f"HIBP catalogue was not valid JSON: {e}") from None
        if not isinstance(raw, list) or not raw:
            raise LiveDataUnavailable("HIBP catalogue was empty")

        breaches = [normalise_breach(b) for b in raw]
        breaches = [b for b in breaches if b["name"]]
        self._cache_write(breaches)
        return breaches

    # --- 3. per-account lookup (PAID endpoint — needs HIBP_API_KEY) -------
    def account_breaches(self, email: str) -> List[dict]:
        """
        Real breaches for one address. Requires a paid HIBP subscription key.

        Without a key this raises LiveDataUnavailable rather than silently
        returning "clean", which would be a dangerous false negative.
        """
        if not self.api_key:
            raise LiveDataUnavailable(
                "Per-account lookup needs a paid HIBP key. Set HIBP_API_KEY to enable it.")
        from urllib.parse import quote

        url = ACCOUNT_URL.format(account=quote(email.strip().lower(), safe=""))
        status, text = self._get(url + "?truncateResponse=false",
                                 {"hibp-api-key": self.api_key})
        if status == 404:
            return []                                   # HIBP's documented "no breaches" answer
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as e:
            raise LiveDataUnavailable(f"HIBP account response was not valid JSON: {e}") from None
        return [normalise_breach(b) for b in (raw if isinstance(raw, list) else [])]


def normalise_breach(b: dict) -> dict:
    """Convert one raw HIBP record into the shape BreachRadar already renders."""
    classes = b.get("DataClasses") or []
    return {
        "name": b.get("Name") or "",
        "title": b.get("Title") or b.get("Name") or "",
        "domain": b.get("Domain") or "",
        "date": b.get("BreachDate") or "1970-01-01",
        "pwn_count": int(b.get("PwnCount") or 0),
        "classes": list(classes),
        "severity": classes_to_severity(classes),
        "password_exposed": bool({"Passwords", "Historical passwords"} & set(classes)),
        "verified": bool(b.get("IsVerified")),
        "sensitive": bool(b.get("IsSensitive")),
        "malware": bool(b.get("IsMalware")),
        "stealer_log": bool(b.get("IsStealerLog")),
    }


@dataclass
class CatalogueStats:
    """Headline numbers computed from the real register — used by the console."""
    total_breaches: int = 0
    total_accounts: int = 0
    verified: int = 0
    with_passwords: int = 0
    latest: List[dict] = field(default_factory=list)
    largest: List[dict] = field(default_factory=list)
    top_classes: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_breaches": self.total_breaches,
            "total_accounts": self.total_accounts,
            "verified": self.verified,
            "with_passwords": self.with_passwords,
            "latest": self.latest,
            "largest": self.largest,
            "top_classes": self.top_classes,
            "source": "Have I Been Pwned — public breach register",
        }


def summarise(breaches: List[dict], limit: int = 6) -> CatalogueStats:
    """Pure function over normalised breaches, so it is trivially testable."""
    if not breaches:
        return CatalogueStats()

    counts: Dict[str, int] = {}
    for b in breaches:
        for c in b.get("classes", []):
            counts[c] = counts.get(c, 0) + 1

    def brief(b: dict) -> dict:
        return {"name": b["name"], "title": b["title"], "date": b["date"],
                "pwn_count": b["pwn_count"], "severity": b["severity"],
                "classes": b["classes"][:4]}

    by_date = sorted(breaches, key=lambda b: b.get("date", ""), reverse=True)
    by_size = sorted(breaches, key=lambda b: b.get("pwn_count", 0), reverse=True)

    return CatalogueStats(
        total_breaches=len(breaches),
        total_accounts=sum(b.get("pwn_count", 0) for b in breaches),
        verified=sum(1 for b in breaches if b.get("verified")),
        with_passwords=sum(1 for b in breaches if b.get("password_exposed")),
        latest=[brief(b) for b in by_date[:limit]],
        largest=[brief(b) for b in by_size[:limit]],
        top_classes=[{"name": k, "count": v}
                     for k, v in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:8]],
    )


def days_since(iso_date: str, today: Optional[date] = None) -> int:
    """Age of a breach in days; tolerant of the malformed dates real feeds contain."""
    today = today or date.today()
    try:
        d = datetime.strptime(iso_date, "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return 0
    return max(0, (today - d).days)
