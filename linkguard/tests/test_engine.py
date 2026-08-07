import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from linkguard.engine import analyze_url, levenshtein, registrable_domain  # noqa: E402


def test_official_domain_is_safe():
    v = analyze_url("https://jmdcareermaker.com/careers/intern")
    assert v.matches_official
    assert v.verdict == "SAFE"
    assert v.risk_score == 0
    assert v.risk_band == "NONE"


def test_typosquat_flagged_as_impersonation():
    v = analyze_url("https://jmdcaremaker.com/login")        # one letter dropped
    assert v.brand_impersonation
    assert v.verdict == "DANGEROUS"
    assert any(s.name == "brand_typosquat" for s in v.signals)


def test_brand_in_subdomain_detected():
    v = analyze_url("https://jmdcareermaker.com.secure-login.ru/verify")
    assert v.registrable_domain == "secure-login.ru"        # real destination, not the firm
    assert v.brand_impersonation
    assert any(s.name == "brand_in_subdomain" for s in v.signals)


def test_userinfo_trap_uses_real_host():
    v = analyze_url("http://jmdcareermaker.com@192.168.0.5/pay")
    assert v.host == "192.168.0.5"                           # destination is after the '@'
    assert any(s.name == "userinfo_trap" for s in v.signals)
    assert v.verdict == "DANGEROUS"


def test_shortener_flagged():
    v = analyze_url("http://bit.ly/jmd-offer")
    assert any(s.name == "url_shortener" for s in v.signals)
    assert v.verdict in {"SUSPICIOUS", "DANGEROUS"}


def test_punycode_homograph_flagged():
    v = analyze_url("https://xn--jmdcareermker-9zb.com/account")
    assert any(s.name == "punycode_homograph" for s in v.signals)


def test_scheme_optional_but_absence_is_not_evidence_of_insecurity():
    """A pasted link with no scheme still parses, and must NOT be called insecure.

    People routinely paste "example.com/page" without typing https://. Treating
    that as a missing-TLS finding was a false positive: it says nothing about the
    site. Only an explicit http:// is evidence, so no_https is asserted on the
    explicit form and denied on the bare one.
    """
    v = analyze_url("jmdcareermaker-hr.xyz/offer-letter")    # no scheme supplied
    assert v.host == "jmdcareermaker-hr.xyz"
    assert not any(s.name == "no_https" for s in v.signals)
    assert any(s.name == "suspicious_tld" for s in v.signals)

    explicit = analyze_url("http://jmdcareermaker-hr.xyz/offer-letter")
    assert any(s.name == "no_https" for s in explicit.signals)


def test_helpers_are_deterministic():
    assert levenshtein("jmdcareermaker", "jmdcaremaker") == 2
    assert levenshtein("abc", "abc") == 0
    assert registrable_domain("a.b.jmdcareermaker.com") == "jmdcareermaker.com"
    assert registrable_domain("foo.co.in") == "foo.co.in"
    assert analyze_url("http://bit.ly/x").to_dict()["risk_score"] == analyze_url("http://bit.ly/x").risk_score


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"  ✓ {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed.")
