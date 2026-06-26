"""
SiteGuard — passive web security-posture scanner.

Designed for assessing JMD's OWN web properties (site + candidate portal). It only
performs safe, non-intrusive GET/HEAD requests and only against a domain the
operator explicitly authorizes. The header-analysis core is a pure function so it
is fully unit-testable offline; live fetching is injected.
"""
from __future__ import annotations

import socket
import ssl
from dataclasses import asdict, dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

SEVERITY_SCORE = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 4, "INFO": 0}

# Security headers we expect on a hardened site.
EXPECTED_HEADERS = {
    "strict-transport-security": ("HIGH", "Enforce HTTPS",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."),
    "content-security-policy": ("HIGH", "Mitigate XSS / injection",
        "Define a Content-Security-Policy restricting script/style/connect sources."),
    "x-frame-options": ("MEDIUM", "Prevent clickjacking",
        "Add 'X-Frame-Options: DENY' (or a frame-ancestors CSP directive)."),
    "x-content-type-options": ("MEDIUM", "Stop MIME sniffing",
        "Add 'X-Content-Type-Options: nosniff'."),
    "referrer-policy": ("LOW", "Limit referrer leakage",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin'."),
    "permissions-policy": ("LOW", "Restrict powerful browser features",
        "Add a 'Permissions-Policy' disabling unused features (camera, geolocation…)."),
}

# Non-intrusive probe paths that should NOT be publicly readable.
SENSITIVE_PATHS = {
    "/.git/config": ("CRITICAL", "Exposed Git repository configuration"),
    "/.env": ("CRITICAL", "Exposed environment/secrets file"),
    "/backup.zip": ("HIGH", "Exposed backup archive"),
    "/.htaccess": ("MEDIUM", "Exposed server config file"),
    "/phpinfo.php": ("HIGH", "Exposed phpinfo() leaks server internals"),
    "/server-status": ("MEDIUM", "Exposed Apache server-status page"),
}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    evidence: str
    remediation: str

    @property
    def score(self) -> int:
        return SEVERITY_SCORE.get(self.severity, 0)


@dataclass
class ScanResult:
    target: str
    grade: str
    posture_score: int                 # 0-100, higher = better
    findings: List[Finding] = field(default_factory=list)
    info: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [{**asdict(f), "score": f.score} for f in self.findings]
        return d


# ---------------------------------------------------------------------------
# Pure analysis core (no network)
# ---------------------------------------------------------------------------
def analyze_headers(headers: Dict[str, str], scheme: str = "https") -> List[Finding]:
    h = {k.lower(): v for k, v in headers.items()}
    findings: List[Finding] = []

    for name, (sev, cat, fix) in EXPECTED_HEADERS.items():
        if name == "strict-transport-security" and scheme != "https":
            continue
        if name not in h:
            findings.append(Finding(
                id=f"hdr-missing-{name}", title=f"Missing header: {name}",
                severity=sev, category=cat, evidence="header not present", remediation=fix))

    # Banner leakage
    for banner in ("server", "x-powered-by", "x-aspnet-version"):
        if banner in h and h[banner].strip():
            findings.append(Finding(
                id=f"banner-{banner}", title=f"Version banner exposed via '{banner}'",
                severity="LOW", category="Information disclosure",
                evidence=f"{banner}: {h[banner]}",
                remediation=f"Suppress or genericise the '{banner}' response header."))

    # Cookie flags
    cookie = h.get("set-cookie", "")
    if cookie:
        low = cookie.lower()
        missing = [flag for flag, tok in
                   (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite"))
                   if tok not in low]
        if missing:
            findings.append(Finding(
                id="cookie-flags", title=f"Cookie missing flags: {', '.join(missing)}",
                severity="MEDIUM", category="Session security",
                evidence=cookie[:120],
                remediation="Set Secure, HttpOnly and SameSite on session cookies."))
    return findings


def grade_findings(target: str, findings: List[Finding], info: Dict[str, str]) -> ScanResult:
    penalty = sum(f.score for f in findings)
    posture = max(0, 100 - penalty)
    grade = ("A" if posture >= 90 else "B" if posture >= 75 else "C" if posture >= 60
             else "D" if posture >= 40 else "F")
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    findings = sorted(findings, key=lambda f: order.index(f.severity))
    return ScanResult(target=target, grade=grade, posture_score=posture,
                      findings=findings, info=info)


# ---------------------------------------------------------------------------
# Live (network) collection — gated behind explicit authorization
# ---------------------------------------------------------------------------
def _tls_info(host: str, port: int = 443) -> Dict[str, str]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                return {"tls_version": ss.version() or "unknown",
                        "cert_subject": dict(x[0] for x in cert.get("subject", ())).get(
                            "commonName", "?"),
                        "cert_expires": cert.get("notAfter", "?")}
    except Exception as e:  # noqa: BLE001
        return {"tls_error": str(e)}


def scan(url: str, authorized: bool, fetcher: Optional[Callable] = None) -> ScanResult:
    """
    fetcher(method, url) -> (status:int, headers:dict, body:str)
    If None, a live requests-based fetcher is used (requires `authorized=True`).
    """
    parsed = urlparse(url if "://" in url else "https://" + url)
    host = parsed.hostname or url
    scheme = parsed.scheme or "https"
    base = f"{scheme}://{host}"

    live = fetcher is None
    if live:
        if not authorized:
            raise PermissionError(
                "Live scan refused: set authorized=True only for domains you own/control.")
        fetcher = _requests_fetcher

    info: Dict[str, str] = {"target": base}
    try:
        status, headers, _ = fetcher("GET", base)
        info["http_status"] = str(status)
    except Exception as e:  # noqa: BLE001
        return grade_findings(base, [Finding(
            "fetch-error", f"Could not reach target: {e}", "INFO",
            "Connectivity", str(e), "Verify the URL/network.")], info)

    findings = analyze_headers(headers, scheme)
    if scheme == "https" and live:
        info.update(_tls_info(host))
        tls = info.get("tls_version", "")
        if tls and tls.replace(".", "").endswith(("10", "11")) or tls in {"TLSv1", "TLSv1.1"}:
            findings.append(Finding("tls-old", f"Weak TLS version: {tls}", "HIGH",
                                    "Transport security", tls, "Disable TLS < 1.2."))

    # Safe path probes
    for path, (sev, title) in SENSITIVE_PATHS.items():
        try:
            st, _, body = fetcher("GET", base + path)
        except Exception:  # noqa: BLE001
            continue
        if st == 200 and body and "<html" not in body[:200].lower():
            findings.append(Finding(f"exposed{path}", title, sev, "Exposed resource",
                                    f"GET {path} -> 200", f"Block public access to {path}."))
    return grade_findings(base, findings, info)


def _requests_fetcher(method: str, url: str) -> Tuple[int, dict, str]:
    import requests
    r = requests.request(method, url, timeout=8, allow_redirects=True,
                         headers={"User-Agent": "SiteGuard/1.0 (+authorized-scan)"})
    return r.status_code, dict(r.headers), r.text[:2000]
