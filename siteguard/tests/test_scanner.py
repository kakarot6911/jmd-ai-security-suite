import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from siteguard.demo import DEMOS  # noqa: E402
from siteguard.scanner import analyze_headers, scan  # noqa: E402


def test_hardened_headers_clean():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin",
        "Permissions-Policy": "geolocation=()",
    }
    assert analyze_headers(headers, "https") == []


def test_missing_headers_flagged():
    findings = analyze_headers({}, "https")
    ids = {f.id for f in findings}
    assert "hdr-missing-content-security-policy" in ids
    assert "hdr-missing-strict-transport-security" in ids


def test_cookie_flags_detected():
    findings = analyze_headers({"set-cookie": "id=1"}, "https")
    assert any(f.id == "cookie-flags" for f in findings)
    findings_ok = analyze_headers(
        {"set-cookie": "id=1; Secure; HttpOnly; SameSite=Strict"}, "https")
    assert not any(f.id == "cookie-flags" for f in findings_ok)


def test_hsts_skipped_on_http():
    findings = analyze_headers({}, "http")
    assert not any(f.id == "hdr-missing-strict-transport-security" for f in findings)


def test_demo_vulnerable_scores_low():
    res = scan("https://vulnerable.demo", authorized=True, fetcher=DEMOS["vulnerable"])
    assert res.grade in {"D", "F"}
    assert any(f.severity == "CRITICAL" for f in res.findings)   # exposed /.env or /.git


def test_demo_hardened_scores_high():
    res = scan("https://hardened.demo", authorized=True, fetcher=DEMOS["hardened"])
    assert res.grade in {"A", "B"}
    assert res.posture_score >= 75


def test_live_requires_authorization():
    try:
        scan("https://example.com", authorized=False)
    except PermissionError:
        return
    raise AssertionError("unauthorized live scan should raise PermissionError")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"  ✓ {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed.")
