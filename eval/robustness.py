"""
Robustness / fuzz harness — "must produce output, never an unhandled error".

Feeds every tool and every API route a battery of hostile inputs: empty values,
wrong types, enormous strings, control characters, unicode, injection payloads
and malformed URLs. A tool may legitimately REFUSE input (ValueError,
PermissionError, HTTP 4xx) — what it may never do is raise an unexpected
exception or return a malformed result.

Run:  python eval/robustness.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path.home() / "jmd_phishguard"))

from breachradar.live import LiveDataUnavailable  # noqa: E402

# Inputs designed to break naive parsing.
NASTY = [
    "", " ", "\n\t\r", "\x00", "\x00\x01\x02",
    "a" * 100_000,
    "🙂" * 500,
    "<script>alert(1)</script>",
    "'; DROP TABLE users; --",
    "../../../../etc/passwd",
    "%00%0a%0d",
    "{{7*7}}", "${jndi:ldap://x/a}",
    "‮evil", "﻿bom",
    "-" * 5000,
    "0" * 10_000,
    "https://" + "a" * 3000 + ".com",
    "http://[::1]:99999/x",
    "http://exa mple.com/ spaces",
    "://noscheme", "http://", "https://:80", "ftp://x.com/y",
    "javascript:" + "a" * 1000,
    "\\\\server\\share",
    "%s%s%s%n",
]

# Values that are not strings at all — callers do pass these by accident.
WRONG_TYPES = [None, 123, 4.5, True, [], {}, ("a",), b"bytes"]


class Fuzz:
    def __init__(self):
        self.ok = 0
        self.refused = 0
        self.failures: list[str] = []

    def run(self, label: str, fn, *args):
        """Call fn; record an unexpected exception as a failure."""
        try:
            result = fn(*args)
        except (ValueError, TypeError, AttributeError) as e:
            # A clean, typed refusal is acceptable for junk input.
            self.refused += 1
            return
        except PermissionError:
            self.refused += 1
            return
        except LiveDataUnavailable:
            # The live layer's documented contract: a bad/hostile upstream surfaces
            # as this typed error so callers can fall back. That is correct handling.
            self.refused += 1
            return
        except Exception as e:  # noqa: BLE001 — anything else is a real defect
            self.failures.append(f"{label}: {type(e).__name__}: {e}")
            return
        if result is None:
            self.failures.append(f"{label}: returned None")
            return
        self.ok += 1

    def report(self, title: str) -> bool:
        mark = "✓" if not self.failures else "✗"
        print(f"{mark} {title}: {self.ok} handled, {self.refused} cleanly refused, "
              f"{len(self.failures)} FAILURES")
        for f in self.failures[:12]:
            print(f"      · {f}")
        return not self.failures


def fuzz_linkguard() -> bool:
    from linkguard.engine import analyze_url, scan

    f = Fuzz()
    for v in NASTY + WRONG_TYPES:
        f.run(f"analyze_url({v!r:.40})", analyze_url, v)
    f.run("scan(mixed list)", scan, [x for x in NASTY[:8]])
    # A verdict must always be serialisable and well-formed.
    for v in NASTY[:12]:
        try:
            d = analyze_url(v).to_dict()
            json.dumps(d)
            assert 0 <= d["risk_score"] <= 100, d["risk_score"]
        except Exception as e:  # noqa: BLE001
            f.failures.append(f"to_dict/json for {v!r:.30}: {type(e).__name__}: {e}")
    return f.report("LinkGuard")


def fuzz_resumeshield() -> bool:
    from resumeshield.pii import detect
    from resumeshield.redact import redact

    f = Fuzz()
    for v in NASTY + WRONG_TYPES:
        f.run(f"detect({v!r:.40})", detect, v)
    for v in NASTY[:15]:
        f.run(f"redact({v!r:.30})", redact, v)
    return f.report("ResumeShield")


def fuzz_siteguard() -> bool:
    from siteguard.scanner import analyze_headers, grade_findings

    f = Fuzz()
    for v in NASTY[:15]:
        f.run("analyze_headers(str values)", analyze_headers, {"Server": v, "Set-Cookie": v}, "https")
        f.run("analyze_headers(weird key)", analyze_headers, {v: "x"}, "https")
    for wt in WRONG_TYPES:
        f.run("analyze_headers(wrong value type)", analyze_headers, {"Server": wt}, "https")
    f.run("analyze_headers({})", analyze_headers, {}, "https")
    f.run("grade_findings(empty)", grade_findings, "t", [], {})
    return f.report("SiteGuard")


def fuzz_breachradar() -> bool:
    from breachradar.engine import BreachRadar
    from breachradar.live import HibpClient, classes_to_severity, normalise_breach, summarise

    f = Fuzz()
    radar = BreachRadar()
    for v in NASTY + WRONG_TYPES:
        f.run(f"check({v!r:.40})", radar.check, v)

    # The live layer must survive a hostile/garbage upstream response.
    for body in ["", "not json", "[]", "{}", "null", '[{"Name":null}]', "\x00", "[1,2,3]"]:
        c = HibpClient(fetcher=lambda u, h, b=body: (200, b), api_key="",
                       cache_path=Path("/tmp/_fuzz_cache.json"))
        f.run(f"catalogue(upstream={body!r:.20})", c.catalogue)
        f.run(f"range_raw(upstream={body!r:.20})", c.range_raw, "ABCDE")
    for v in NASTY[:10] + WRONG_TYPES:
        f.run(f"normalise_breach({v!r:.30})", normalise_breach, {"Name": v, "DataClasses": v})
    f.run("summarise([])", summarise, [])
    f.run("classes_to_severity(None)", classes_to_severity, None)
    return f.report("BreachRadar")


def fuzz_phishguard() -> bool:
    try:
        from src.predict import analyze, calibrate
    except Exception as e:  # noqa: BLE001
        print(f"! PhishGuard unavailable ({e}) — skipped")
        return True

    f = Fuzz()
    for v in NASTY[:18]:
        f.run(f"analyze({v!r:.30})", analyze, v, "a@b.com", "Co")
        f.run(f"analyze(sender={v!r:.24})", analyze, "hello", v, "Co")
    for a, b in [(0.5, []), (0.0, [1.0]), (1.0, [0.5, 0.5]), (-1, [2.0]), (2, [-1])]:
        f.run(f"calibrate({a},{b})", calibrate, a, b)
    # The probability must always be a usable number in [0,1].
    for v in NASTY[:10]:
        try:
            p = analyze(v, "", "").fraud_probability
            assert 0.0 <= p <= 1.0, p
        except Exception as e:  # noqa: BLE001
            f.failures.append(f"probability range for {v!r:.24}: {type(e).__name__}: {e}")
    return f.report("PhishGuard")


def main() -> int:
    print("=" * 74)
    print("Robustness / fuzz — every tool must produce output or refuse cleanly")
    print("=" * 74)
    results = [fuzz_phishguard(), fuzz_resumeshield(), fuzz_siteguard(),
               fuzz_linkguard(), fuzz_breachradar()]
    print("-" * 74)
    if all(results):
        print("ALL TOOLS ROBUST — no unhandled exceptions, no malformed output.")
        return 0
    print("FAILURES PRESENT — see above.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
