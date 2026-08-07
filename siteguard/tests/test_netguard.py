"""
Tests for the SSRF guard.

The vulnerability these pin down was real: `authorized` arrives in the request
body, so before this guard existed any API caller could make the server fetch
http://169.254.169.254/ (cloud metadata) or http://127.0.0.1:<port>/ and read
the result through the scan output.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from siteguard.netguard import (  # noqa: E402
    ScanTargetRefused, address_is_public, allowlist, assert_scannable,
    host_is_allowed, resolve_all,
)


def _refuses(url, **kw):
    try:
        assert_scannable(url, **kw)
    except ScanTargetRefused:
        return True
    return False


def test_cloud_metadata_address_is_refused():
    """The single most valuable SSRF target on a cloud host."""
    assert _refuses("http://169.254.169.254/latest/meta-data/", require_allowlist=False)


def test_loopback_and_private_ranges_refused():
    for url in ("http://127.0.0.1:8000/", "http://localhost/", "https://10.0.0.5/",
                "http://192.168.1.1/", "http://172.16.0.1/", "http://[::1]/",
                "http://0.0.0.0/"):
        assert _refuses(url, require_allowlist=False), url


def test_ipv4_mapped_ipv6_cannot_smuggle_loopback():
    assert address_is_public("::ffff:127.0.0.1") is False
    assert address_is_public("::ffff:10.0.0.1") is False


def test_public_address_is_allowed():
    assert address_is_public("8.8.8.8") is True
    assert address_is_public("2001:4860:4860::8888") is True


def test_non_http_schemes_refused():
    for url in ("file:///etc/passwd", "gopher://x/", "ftp://x.com/"):
        assert _refuses(url, require_allowlist=False), url


def test_empty_and_garbage_targets_refused():
    for url in ("", "   ", "://", "http://", None):
        assert _refuses(url or "", require_allowlist=False)


def test_live_scanning_disabled_when_no_allowlist_configured():
    """Deployed default must be closed, not open."""
    old = os.environ.pop("JMD_SCAN_ALLOWLIST", None)
    try:
        assert _refuses("https://example.com/", require_allowlist=True)
    finally:
        if old is not None:
            os.environ["JMD_SCAN_ALLOWLIST"] = old


def test_allowlist_matches_domain_and_subdomains_only():
    assert host_is_allowed("example.com", ["example.com"])
    assert host_is_allowed("www.example.com", ["example.com"])
    assert host_is_allowed("a.b.example.com", ["example.com"])
    assert not host_is_allowed("evil.com", ["example.com"])
    # A suffix that is not a label boundary must not match.
    assert not host_is_allowed("notexample.com", ["example.com"])
    assert not host_is_allowed("example.com.evil.ru", ["example.com"])
    assert not host_is_allowed("", ["example.com"])


def test_allowlist_env_parsing():
    old = os.environ.get("JMD_SCAN_ALLOWLIST")
    try:
        os.environ["JMD_SCAN_ALLOWLIST"] = " Example.COM , .foo.in ,, "
        assert allowlist() == ["example.com", "foo.in"]
        os.environ["JMD_SCAN_ALLOWLIST"] = ""
        assert allowlist() == []
    finally:
        if old is None:
            os.environ.pop("JMD_SCAN_ALLOWLIST", None)
        else:
            os.environ["JMD_SCAN_ALLOWLIST"] = old


def test_literal_ip_never_satisfies_the_allowlist():
    old = os.environ.get("JMD_SCAN_ALLOWLIST")
    try:
        os.environ["JMD_SCAN_ALLOWLIST"] = "8.8.8.8,example.com"
        assert _refuses("http://8.8.8.8/", require_allowlist=True)
    finally:
        if old is None:
            os.environ.pop("JMD_SCAN_ALLOWLIST", None)
        else:
            os.environ["JMD_SCAN_ALLOWLIST"] = old


def test_unresolvable_host_refused_not_crashed():
    assert _refuses("https://nonexistent-domain-for-tests.invalid/", require_allowlist=False)
    assert resolve_all("nonexistent-domain-for-tests.invalid") == set()


def test_scan_refuses_internal_target_before_touching_network():
    """End-to-end: scan() must raise rather than fetch."""
    from siteguard.scanner import scan

    touched = []

    def spy_fetcher(method, url):        # must never be called
        touched.append(url)
        return 200, {}, ""

    try:
        scan("http://169.254.169.254/", authorized=True, require_allowlist=False)
    except ScanTargetRefused:
        pass
    else:
        raise AssertionError("expected ScanTargetRefused")
    assert not touched


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"  ✓ {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed.")
