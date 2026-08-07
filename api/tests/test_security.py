"""
Unit tests for the API hardening layer (api/security.py) and the wired-in
middleware (api/main.harden).

No httpx / TestClient needed: the ``@app.middleware`` decorator returns the
function unchanged, so we exercise ``harden`` directly against a tiny fake
request and a fake ``call_next``.

Run:  python api/tests/test_security.py
"""
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from starlette.responses import Response  # noqa: E402
from api import security as sec  # noqa: E402
from api import main  # noqa: E402


# --- fakes -----------------------------------------------------------------
class _URL:
    def __init__(self, path):
        self.path = path


class _Client:
    def __init__(self, host):
        self.host = host


class _Request:
    def __init__(self, path, headers=None, host="1.2.3.4"):
        self.url = _URL(path)
        self.headers = headers or {}
        self.client = _Client(host)


async def _ok_next(_request):
    return Response("ok")


def _run_harden(request):
    return asyncio.run(main.harden(request, _ok_next))


def _clear_auth_env():
    for k in ("JMD_API_KEY", "JMD_CORS_ORIGINS", "JMD_MAX_BODY_BYTES"):
        os.environ.pop(k, None)


# --- key check -------------------------------------------------------------
def test_key_is_valid():
    assert sec.key_is_valid("secret", ["secret"])
    assert sec.key_is_valid("b", ["a", "b", "c"])
    assert not sec.key_is_valid("wrong", ["secret"])
    assert not sec.key_is_valid("", ["secret"])
    assert not sec.key_is_valid(None, ["secret"])
    assert not sec.key_is_valid("secret", [])


# --- rate limiter ----------------------------------------------------------
def test_rate_limiter_allows_then_blocks():
    rl = sec.RateLimiter(limit=3, window_seconds=60)
    assert all(rl.allow("client", now=0)[0] for _ in range(3))
    ok, retry = rl.allow("client", now=0)
    assert not ok and retry > 0


def test_rate_limiter_is_per_client():
    rl = sec.RateLimiter(limit=1, window_seconds=60)
    assert rl.allow("a", now=0)[0]
    assert not rl.allow("a", now=0)[0]
    assert rl.allow("b", now=0)[0]        # different client unaffected


def test_rate_limiter_window_expiry():
    rl = sec.RateLimiter(limit=1, window_seconds=10)
    assert rl.allow("a", now=0)[0]
    assert not rl.allow("a", now=5)[0]    # still inside window
    assert rl.allow("a", now=11)[0]       # window elapsed → allowed again


# --- config parsing --------------------------------------------------------
def test_config_from_env():
    _clear_auth_env()
    assert sec.configured_api_keys() == [] and not sec.auth_enabled()
    assert sec.cors_origins() == ["*"]
    os.environ["JMD_API_KEY"] = "k1, k2 ,, k3"
    os.environ["JMD_CORS_ORIGINS"] = "https://a.com, https://b.com"
    os.environ["JMD_MAX_BODY_BYTES"] = "1024"
    assert sec.configured_api_keys() == ["k1", "k2", "k3"] and sec.auth_enabled()
    assert sec.cors_origins() == ["https://a.com", "https://b.com"]
    assert sec.max_body_bytes() == 1024
    _clear_auth_env()


def test_client_id_prefers_key():
    assert sec.client_id_for("1.2.3.4", "abcdefgh123").startswith("key:")
    assert sec.client_id_for("1.2.3.4", None) == "ip:1.2.3.4"
    assert sec.client_id_for(None, None) == "ip:unknown"


# --- middleware: security headers on every response ------------------------
def test_middleware_adds_security_headers():
    _clear_auth_env()
    resp = _run_harden(_Request("/health"))
    assert resp.status_code == 200
    for header in ("X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"):
        assert header in resp.headers, f"missing {header}"
    assert resp.headers["X-Frame-Options"] == "DENY"


# --- middleware: auth gate -------------------------------------------------
def test_middleware_auth_blocks_without_key():
    os.environ["JMD_API_KEY"] = "topsecret"
    try:
        resp = _run_harden(_Request("/linkguard/analyze"))
        assert resp.status_code == 401
        resp_ok = _run_harden(_Request("/linkguard/analyze", headers={"x-api-key": "topsecret"}))
        assert resp_ok.status_code == 200
        # metadata routes stay open even with auth on
        assert _run_harden(_Request("/health")).status_code == 200
    finally:
        _clear_auth_env()
        main._limiter.reset()


def test_middleware_disabled_auth_is_open():
    _clear_auth_env()
    main._limiter.reset()
    assert _run_harden(_Request("/linkguard/analyze")).status_code == 200


# --- middleware: body size cap ---------------------------------------------
def test_middleware_rejects_oversized_body():
    _clear_auth_env()
    big = str(sec.max_body_bytes() + 1)
    resp = _run_harden(_Request("/resumeshield/redact", headers={"content-length": big}))
    assert resp.status_code == 413


# --- middleware: rate limit ------------------------------------------------
def test_middleware_rate_limits():
    _clear_auth_env()
    saved = main._limiter
    main._limiter = sec.RateLimiter(limit=2, window_seconds=60)
    try:
        assert _run_harden(_Request("/breachradar/check", host="9.9.9.9")).status_code == 200
        assert _run_harden(_Request("/breachradar/check", host="9.9.9.9")).status_code == 200
        blocked = _run_harden(_Request("/breachradar/check", host="9.9.9.9"))
        assert blocked.status_code == 429
        assert "Retry-After" in blocked.headers
    finally:
        main._limiter = saved



def test_rate_limiter_evicts_idle_clients():
    """Without eviction, one deque per client id leaks memory forever — a slow
    exhaustion vector for any endpoint reachable by many distinct IPs."""
    rl = sec.RateLimiter(limit=5, window_seconds=1)
    t = 0.0
    for i in range(20_000):
        rl.allow(f"ip:{i}", now=t)
        t += 0.01
    # 20k distinct clients over 200 simulated seconds; only recent ones survive.
    assert rl.tracked_clients() < 5_000, rl.tracked_clients()


def test_rate_limiter_eviction_does_not_forgive_active_clients():
    """Sweeping must not reset a client that is still inside its window."""
    rl = sec.RateLimiter(limit=3, window_seconds=100)
    for i in range(3):
        assert rl.allow("busy", now=float(i))[0]
    # Force a sweep well past SWEEP_EVERY_SECONDS but still inside the window.
    ok, _ = rl.allow("busy", now=70.0)
    assert ok is False


def test_rate_limiter_is_thread_safe_under_contention():
    import threading

    rl = sec.RateLimiter(limit=10_000, window_seconds=60)
    errors = []

    def hammer():
        try:
            for _ in range(500):
                rl.allow("shared")
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=hammer) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors

if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"  ✓ {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed.")
