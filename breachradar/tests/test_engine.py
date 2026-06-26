import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from breachradar.engine import BreachRadar, sha1_hex  # noqa: E402

TODAY = date(2026, 6, 27)
radar = BreachRadar()


def test_known_exposed_account_flagged():
    x = radar.check("akash.mishra@jmdcareermaker.com", today=TODAY)
    assert x.breaches
    assert x.password_exposed
    assert x.risk_band in {"HIGH", "CRITICAL"}


def test_clean_account_is_none():
    x = radar.check("definitely-not-in-corpus-xyz@nowhere.test", today=TODAY)
    assert x.breaches == []
    assert x.risk_band == "NONE"
    assert x.risk_score == 0


def test_k_anonymity_prefix_lookup():
    email = "hr@jmdcareermaker.com"
    full = sha1_hex(email)
    bucket = radar.range_query(full[:5])          # only prefix is "sent"
    assert full[5:] in bucket                       # suffix matched locally
    # the prefix bucket must not trivially reveal the exact address
    assert all(len(k) == len(full) - 5 for k in bucket)


def test_high_value_target_detection():
    x = radar.check("hr@jmdcareermaker.com", today=TODAY)
    assert x.high_value_target


def test_scan_orders_by_risk():
    res = radar.scan(radar.org_emails)
    scores = [x.risk_score for x in res]
    assert scores == sorted(scores, reverse=True)


def test_recency_reduces_score():
    # Same lookup assessed far in the future should score <= present-day score.
    e = "akash.mishra@jmdcareermaker.com"
    now = radar.check(e, today=TODAY).risk_score
    future = radar.check(e, today=date(2035, 1, 1)).risk_score
    assert future <= now


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"  ✓ {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed.")
