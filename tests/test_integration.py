"""
Integration tests for the unified layer + API route functions.
No network or httpx needed — route handlers are called directly with their models.
Run:  python tests/test_integration.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from console import integrations as ig  # noqa: E402
from api.main import (  # noqa: E402
    PhishIn, ResumeIn, SiteIn, LinkIn, EmailIn,
    health, tools, phishguard, resumeshield, siteguard, linkguard,
    breachradar_check, breachradar_org,
)
from fastapi import HTTPException  # noqa: E402

EXPECTED_TOOLS = {"phishguard", "resumeshield", "siteguard", "linkguard", "breachradar"}


def test_health_and_tools():
    h = health()
    assert h["status"] == "ok"
    assert set(h["modules"]) == EXPECTED_TOOLS
    assert len(tools()) == len(EXPECTED_TOOLS)


def test_phishguard_route_scam():
    out = phishguard(PhishIn(text="Pay Rs 1999 registration fee now! Limited slots",
                             sender_email="x@gmail.com", claimed_company="JMD The Career Maker"))
    assert out["risk_band"] in {"CRITICAL", "HIGH"}
    assert out["hard_block"] is True


def test_resumeshield_route_redacts():
    out = resumeshield(ResumeIn(text="Aadhaar 2994 1855 6015 PAN ABCDE1234F"))
    assert "ABCDE1234F" not in out["redacted_text"]
    assert out["risk_band"] in {"HIGH", "CRITICAL"}


def test_siteguard_demo_route():
    out = siteguard(SiteIn(demo="vulnerable"))
    assert out["grade"] in {"D", "F"}


def test_siteguard_unauthorized_blocked():
    try:
        siteguard(SiteIn(url="https://example.com", authorized=False))
    except HTTPException as e:
        assert e.status_code == 403
        return
    raise AssertionError("unauthorized live scan must be blocked with 403")


def test_linkguard_route_flags_typosquat():
    out = linkguard(LinkIn(url="https://jmdcaremaker.com/login"))
    assert out["brand_impersonation"] is True
    assert out["verdict"] == "DANGEROUS"
    assert any(s["name"] == "brand_typosquat" for s in out["signals"])
    assert "ml_probability" in out                      # ML field always exposed


def test_linkguard_route_passes_official():
    out = linkguard(LinkIn(url="https://jmdcareermaker.com/careers"))
    assert out["matches_official"] is True
    assert out["verdict"] == "SAFE"


def test_breachradar_routes():
    out = breachradar_check(EmailIn(email="akash.mishra@jmdcareermaker.com"))
    assert out["exposed"] and out["risk_band"] in {"CRITICAL", "HIGH"}
    org = breachradar_org()
    assert len(org) == 8


def test_integration_adapter_consistency():
    # Adapter and route must agree.
    a = ig.breachradar_check("hr@jmdcareermaker.com")
    b = breachradar_check(EmailIn(email="hr@jmdcareermaker.com"))
    assert a["risk_score"] == b["risk_score"]


def test_web_frontend_present_and_mounted():
    root = Path(__file__).resolve().parents[1]
    for f in ("web/index.html", "web/styles.css", "web/app.js"):
        assert (root / f).exists(), f"missing {f}"
    # the static site must be mounted on the app so the backend serves it
    import api.main as apimod
    assert apimod.WEB_DIR.exists()
    mounts = [r for r in apimod.app.routes if getattr(r, "name", "") == "web"]
    assert mounts, "web StaticFiles mount not registered"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"  ✓ {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed.")
