"""
Hardening primitives for the JMD Security Suite API.

Everything here is written as small, pure, unit-testable pieces (no FastAPI
imports) so the logic can be verified without spinning up a server or pulling
in httpx.  ``main.py`` wires them into Starlette middleware.

Configuration is entirely environment-driven so the suite stays open and
frictionless for local development / the existing test-suite, and locks down in
production simply by setting env vars:

    JMD_API_KEY          comma-separated API keys; if unset, auth is DISABLED
    JMD_RATE_LIMIT       max requests per window per client (default 60)
    JMD_RATE_WINDOW      window length in seconds (default 60)
    JMD_CORS_ORIGINS     comma-separated allowed origins (default "*")
    JMD_MAX_BODY_BYTES   reject bodies larger than this (default 65536)
"""
from __future__ import annotations

import hmac
import os
import threading
import time
from collections import deque
from typing import Deque, Dict, Iterable

# --- Config helpers --------------------------------------------------------


def _split_env(name: str) -> list[str]:
    return [v.strip() for v in os.environ.get(name, "").split(",") if v.strip()]


def configured_api_keys() -> list[str]:
    """API keys accepted by the server. Empty list ⇒ auth disabled."""
    return _split_env("JMD_API_KEY")


def auth_enabled() -> bool:
    return bool(configured_api_keys())


def cors_origins() -> list[str]:
    origins = _split_env("JMD_CORS_ORIGINS")
    return origins or ["*"]


def max_body_bytes() -> int:
    return _int_env("JMD_MAX_BODY_BYTES", 65_536)


def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


# --- API-key check ---------------------------------------------------------


def key_is_valid(provided: str | None, allowed: Iterable[str]) -> bool:
    """
    Constant-time membership test for an API key.

    Returns False for a missing/empty key. Uses ``hmac.compare_digest`` so a
    valid key can't be discovered by timing the comparison.
    """
    if not provided:
        return False
    for candidate in allowed:
        if hmac.compare_digest(provided, candidate):
            return True
    return False


# --- Rate limiter (fixed sliding window, in-memory) ------------------------


class RateLimiter:
    """
    Thread-safe sliding-window limiter keyed by an arbitrary client id.

    Not distributed — fine for a single-process container / free-tier host.
    ``allow`` returns (ok, retry_after_seconds).
    """

    def __init__(self, limit: int, window_seconds: float) -> None:
        self.limit = max(1, int(limit))
        self.window = float(window_seconds)
        self._hits: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, client_id: str, now: float | None = None) -> tuple[bool, float]:
        now = time.monotonic() if now is None else now
        cutoff = now - self.window
        with self._lock:
            q = self._hits.setdefault(client_id, deque())
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= self.limit:
                retry_after = max(0.0, q[0] + self.window - now)
                return False, retry_after
            q.append(now)
            return True, 0.0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


# --- Security headers ------------------------------------------------------

SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    ),
}


def rate_limiter_from_env() -> RateLimiter:
    return RateLimiter(
        limit=_int_env("JMD_RATE_LIMIT", 60),
        window_seconds=_int_env("JMD_RATE_WINDOW", 60),
    )


def client_id_for(ip: str | None, api_key: str | None) -> str:
    """Prefer the API key (per-caller) over IP (shared behind proxies/NAT)."""
    if api_key:
        return f"key:{api_key[:8]}"
    return f"ip:{ip or 'unknown'}"
