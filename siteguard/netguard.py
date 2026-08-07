"""
SSRF guard for SiteGuard's live scanner.

SiteGuard is the one tool that makes the server fetch a caller-supplied URL, which
makes it the one place a caller can turn this service into a proxy for reaching
things it should not reach: cloud metadata (169.254.169.254), container-internal
services, the host's own admin ports, or the private RFC1918 network around it.

Two independent gates, both enforced server-side:

  1. **Destination filter** — the hostname is resolved and EVERY returned address
     must be a public unicast address. A name that resolves to loopback, private,
     link-local, reserved or multicast space is refused. This is what stops
     ``http://169.254.169.254/`` and ``http://localhost:6379/`` regardless of what
     the caller claims.

  2. **Allowlist** — for network-exposed callers, the target's registrable domain
     must appear in ``JMD_SCAN_ALLOWLIST``. Unset ⇒ live scanning is disabled for
     those callers entirely, so a deployed instance is never an open scanning
     proxy. Offline demo mode is unaffected.

A trusted local operator (the CLI) passes ``require_allowlist=False`` and keeps
gate 1 only — resolving to a private address is never legitimate for this tool.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from typing import Iterable, List, Set
from urllib.parse import urlparse


class ScanTargetRefused(PermissionError):
    """Raised when a target is not permitted. Subclasses PermissionError so the
    API's existing 403 handling covers it without changes."""


def allowlist() -> List[str]:
    """Registrable domains this deployment may live-scan. Empty ⇒ none."""
    raw = os.environ.get("JMD_SCAN_ALLOWLIST", "")
    return [d.strip().lower().lstrip(".") for d in raw.split(",") if d.strip()]


def _registrable(host: str) -> str:
    """Last two labels — sufficient for matching an operator-configured allowlist."""
    parts = [p for p in host.lower().split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def host_is_allowed(host: str, allowed: Iterable[str]) -> bool:
    """True when host equals, or is a sub-domain of, an allowlisted domain."""
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    for entry in allowed:
        if host == entry or host.endswith("." + entry):
            return True
    return False


def address_is_public(addr: str) -> bool:
    """False for anything an external scanner has no business reaching."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped          # ::ffff:127.0.0.1 must not slip through
    blocked = (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        or ip.is_multicast or ip.is_unspecified
    )
    # is_site_local exists only on IPv6Address (the deprecated fec0::/10 range).
    if isinstance(ip, ipaddress.IPv6Address):
        blocked = blocked or ip.is_site_local
    return not blocked


def resolve_all(host: str, port: int = 443) -> Set[str]:
    """Every address the hostname resolves to. Empty set on resolution failure."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, ValueError, OSError):
        return set()
    return {info[4][0] for info in infos}


def assert_scannable(url: str, *, require_allowlist: bool = True) -> str:
    """
    Validate a live-scan target. Returns the hostname, or raises ScanTargetRefused.

    Call this immediately before fetching. It cannot fully close a DNS-rebinding
    race (the name could resolve differently on the real request), but it removes
    the entire class of directly-supplied internal targets, which is what an
    attacker actually reaches for.
    """
    parsed = urlparse(url if "://" in (url or "") else f"https://{url or ''}")
    host = (parsed.hostname or "").strip().rstrip(".")
    if not host:
        raise ScanTargetRefused("No hostname in the scan target.")

    if parsed.scheme not in ("http", "https"):
        raise ScanTargetRefused(
            f"Only http/https targets can be scanned (got '{parsed.scheme}').")

    # A literal IP is never an allowlisted business domain, and the public check
    # below would reject the interesting ones anyway — refuse plainly.
    try:
        ipaddress.ip_address(host)
        is_literal_ip = True
    except ValueError:
        is_literal_ip = False

    if require_allowlist:
        allowed = allowlist()
        if not allowed:
            raise ScanTargetRefused(
                "Live scanning is disabled: no JMD_SCAN_ALLOWLIST is configured. "
                "Set it to the domains this deployment is authorised to scan, "
                "or use offline demo mode.")
        if is_literal_ip or not host_is_allowed(host, allowed):
            raise ScanTargetRefused(
                f"'{host}' is not in JMD_SCAN_ALLOWLIST. Live scanning is limited to "
                f"domains this deployment owns.")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    addresses = resolve_all(host, port)
    if not addresses:
        raise ScanTargetRefused(f"'{host}' could not be resolved.")

    private = sorted(a for a in addresses if not address_is_public(a))
    if private:
        raise ScanTargetRefused(
            f"'{host}' resolves to non-public address(es) {', '.join(private)}. "
            "Scanning internal, loopback or cloud-metadata addresses is refused.")

    return host
