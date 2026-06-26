"""Offline demo fetchers so SiteGuard runs (and tests) with no network."""
from __future__ import annotations

from typing import Tuple

_HARDENED = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=(), camera=()",
    "set-cookie": "session=abc; Secure; HttpOnly; SameSite=Strict",
}

_VULNERABLE = {
    "server": "Apache/2.4.29 (Ubuntu)",
    "x-powered-by": "PHP/7.2.1",
    "set-cookie": "PHPSESSID=xyz",            # no flags
    # no security headers at all
}

_EXPOSED_PATHS = {"/.env", "/.git/config"}


def hardened_fetcher(method: str, url: str) -> Tuple[int, dict, str]:
    if any(url.endswith(p) for p in _EXPOSED_PATHS):
        return 404, {}, "not found"
    return 200, dict(_HARDENED), "<html>ok</html>"


def vulnerable_fetcher(method: str, url: str) -> Tuple[int, dict, str]:
    for p in _EXPOSED_PATHS:
        if url.endswith(p):
            return 200, {"content-type": "text/plain"}, "SECRET_KEY=leaked"
    return 200, dict(_VULNERABLE), "<html>ok</html>"


DEMOS = {"hardened": hardened_fetcher, "vulnerable": vulnerable_fetcher}
