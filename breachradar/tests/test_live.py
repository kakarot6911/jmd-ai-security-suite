"""
Tests for the REAL-data (HIBP) layer.

Every test injects a stub fetcher, so this file makes no network calls and is
fully deterministic — the point is to prove the parsing, grading, caching and
failure handling are correct, not that HIBP is up.
"""
import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from breachradar.live import (  # noqa: E402
    CACHE_TTL_SECONDS, HibpClient, LiveDataUnavailable, classes_to_severity,
    days_since, normalise_breach, password_advice, severity_for_count, summarise,
)

# A real range response looks like "SUFFIX:COUNT" lines, CRLF separated.
SUFFIX = "B" * 35
RANGE_BODY = f"{'A' * 35}:12\r\n{SUFFIX}:2266543\r\n{'C' * 35}:1\r\n"

RAW_BREACHES = [
    {"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com", "BreachDate": "2013-10-04",
     "PwnCount": 152445165, "DataClasses": ["Email addresses", "Passwords", "Usernames"],
     "IsVerified": True, "IsSensitive": False},
    {"Name": "Small", "Title": "Small Site", "Domain": "s.com", "BreachDate": "2024-01-09",
     "PwnCount": 500, "DataClasses": ["Email addresses", "Names"],
     "IsVerified": False, "IsSensitive": False},
    {"Name": "Odd", "Title": "Odd", "BreachDate": "2020-02-02", "PwnCount": 7,
     "DataClasses": ["Browsing histories"], "IsVerified": True},
]


def fetcher_for(body, status=200):
    calls = []

    def _f(url, headers):
        calls.append((url, headers))
        return status, body

    _f.calls = calls
    return _f


def client(body="", status=200, tmp_name="cache_test.json", now=None):
    tmp = Path(__file__).resolve().parent / tmp_name
    if tmp.exists():
        tmp.unlink()
    return HibpClient(fetcher=fetcher_for(body, status), api_key="", cache_path=tmp,
                      now=now or (lambda: 1000.0))


# --- password exposure -----------------------------------------------------
def test_password_found_returns_real_count():
    c = client(RANGE_BODY)
    r = c.password_exposure_by_prefix("21BD1", SUFFIX)
    assert r.times_seen == 2266543
    assert r.compromised is True
    assert r.candidates_returned == 3
    assert r.to_dict()["severity"] == "CRITICAL"


def test_password_absent_scores_zero():
    c = client(RANGE_BODY)
    r = c.password_exposure_by_prefix("21BD1", "F" * 35)
    assert r.times_seen == 0
    assert r.compromised is False
    assert r.to_dict()["severity"] == "NONE"


def test_only_the_prefix_is_ever_sent():
    """The whole privacy claim: the suffix must never appear in the request."""
    c = client(RANGE_BODY)
    c.password_exposure_by_prefix("21BD1", SUFFIX)
    url, _ = c._fetch.calls[0]
    assert url.endswith("/range/21BD1")
    assert SUFFIX not in url


def test_bad_prefix_rejected():
    c = client(RANGE_BODY)
    for bad in ["", "21BD", "21BD12", "ZZZZZ", "21bd!"]:
        try:
            c.password_exposure_by_prefix(bad, SUFFIX)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for prefix {bad!r}")


def test_severity_thresholds():
    assert severity_for_count(0) == "NONE"
    assert severity_for_count(5) == "LOW"
    assert severity_for_count(50) == "MEDIUM"
    assert severity_for_count(5_000) == "HIGH"
    assert severity_for_count(2_000_000) == "CRITICAL"
    assert len(password_advice(0)) >= 2 and len(password_advice(10)) >= 3


# --- catalogue -------------------------------------------------------------
def test_catalogue_normalises_real_records():
    c = client(json.dumps(RAW_BREACHES))
    cat = c.catalogue()
    adobe = [b for b in cat if b["name"] == "Adobe"][0]
    assert adobe["pwn_count"] == 152445165
    assert adobe["severity"] == "HIGH"          # contains Passwords
    assert adobe["password_exposed"] is True
    assert adobe["verified"] is True
    small = [b for b in cat if b["name"] == "Small"][0]
    assert small["severity"] == "MEDIUM"         # emails/names only
    assert small["password_exposed"] is False


def test_catalogue_is_cached_and_ttl_expires():
    c = client(json.dumps(RAW_BREACHES), tmp_name="cache_ttl.json")
    c.catalogue()
    assert len(c._fetch.calls) == 1
    c.catalogue()                                 # served from disk cache
    assert len(c._fetch.calls) == 1
    c._now = lambda: 1000.0 + CACHE_TTL_SECONDS + 1
    c.catalogue()                                 # cache stale -> refetch
    assert len(c._fetch.calls) == 2


def test_summarise_computes_real_headline_numbers():
    s = summarise([normalise_breach(b) for b in RAW_BREACHES])
    assert s.total_breaches == 3
    assert s.total_accounts == 152445165 + 500 + 7
    assert s.verified == 2
    assert s.with_passwords == 1
    assert s.largest[0]["name"] == "Adobe"        # biggest first
    assert s.latest[0]["name"] == "Small"         # most recent first
    assert s.top_classes[0]["name"] == "Email addresses"
    assert s.to_dict()["source"].startswith("Have I Been Pwned")


def test_summarise_handles_empty_feed():
    s = summarise([])
    assert s.total_breaches == 0 and s.total_accounts == 0
    assert s.latest == [] and s.top_classes == []


def test_class_grading():
    assert classes_to_severity(["Passwords"]) == "HIGH"
    assert classes_to_severity(["Government issued IDs"]) == "HIGH"
    assert classes_to_severity(["Email addresses"]) == "MEDIUM"
    assert classes_to_severity(["Browsing histories"]) == "LOW"
    assert classes_to_severity([]) == "LOW"


def test_malformed_dates_do_not_crash():
    assert days_since("not-a-date") == 0
    assert days_since(None) == 0
    assert days_since("2020-01-01", today=date(2020, 1, 31)) == 30
    b = normalise_breach({})                      # completely empty record
    assert b["date"] == "1970-01-01" and b["pwn_count"] == 0


# --- failure handling ------------------------------------------------------
def test_upstream_error_raises_typed_exception_after_retry():
    c = client("boom", status=500)
    try:
        c.catalogue()
    except LiveDataUnavailable:
        assert len(c._fetch.calls) == 2           # retried exactly once
        return
    raise AssertionError("expected LiveDataUnavailable")


def test_transport_exception_is_wrapped():
    def explode(url, headers):
        raise OSError("network down")

    c = HibpClient(fetcher=explode, api_key="", cache_path=Path("/tmp/none.json"))
    try:
        c.catalogue()
    except LiveDataUnavailable as e:
        assert "network down" in str(e)
        return
    raise AssertionError("expected LiveDataUnavailable")


def test_invalid_json_catalogue_is_reported_not_crashed():
    c = client("<html>maintenance</html>", tmp_name="cache_bad.json")
    try:
        c.catalogue()
    except LiveDataUnavailable as e:
        assert "valid JSON" in str(e)
        return
    raise AssertionError("expected LiveDataUnavailable")


def test_paid_account_lookup_requires_key():
    c = client("[]")
    try:
        c.account_breaches("hr@jmdcareermaker.com")
    except LiveDataUnavailable as e:
        assert "HIBP_API_KEY" in str(e)
        assert not c._fetch.calls        # must not call the paid endpoint keyless
        return
    raise AssertionError("expected LiveDataUnavailable")


def test_paid_account_lookup_404_means_clean():
    tmp = Path(__file__).resolve().parent / "cache_acct.json"
    c = HibpClient(fetcher=fetcher_for("Not found", 404), api_key="k", cache_path=tmp)
    assert c.account_breaches("nobody@example.com") == []


def _cleanup():
    for name in ["cache_test.json", "cache_ttl.json", "cache_bad.json", "cache_acct.json"]:
        p = Path(__file__).resolve().parent / name
        if p.exists():
            p.unlink()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    try:
        for fn in fns:
            fn(); print(f"  ✓ {fn.__name__}")
    finally:
        _cleanup()
    print(f"\n{len(fns)}/{len(fns)} tests passed.")
