"""
LinkGuard core — lexical safety analysis of a single URL.

A career-consulting firm e-mails job links to candidates and receives links back
every day. Scammers exploit this with lookalike domains (typosquats of the firm's
real domain), URL shorteners that hide the destination, homograph/punycode tricks,
and `user@host` credential traps. LinkGuard inspects the URL string itself — purely
offline, no network calls — and explains every signal it fires so a recruiter can
decide whether a link is safe to click or forward.

It complements PhishGuard (which scores the e-mail *body*) by scrutinising the
*links*. Deterministic: the same URL always yields the same verdict.
"""
from __future__ import annotations

import functools
import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlsplit

# The firm's genuine domain(s). Anything that looks-but-isn't is impersonation.
BRAND_DOMAINS = ("jmdcareermaker.com",)

# When a trained ML model is present, a predicted-malicious probability at/above
# this threshold contributes an extra weighted signal (skipped for the official
# domain, so a genuine link is never penalised by the model).
ML_THRESHOLD = 0.5


@functools.lru_cache(maxsize=1)
def _model():
    """Load the trained URL classifier if it exists; otherwise run heuristics only."""
    try:
        from linkguard.model import load_model
        return load_model()
    except Exception:
        return None

# Registrable-domain extraction without a public-suffix dependency: handle the
# common multi-label suffixes we actually care about, else fall back to last two.
MULTI_SUFFIX = {
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "firm.in", "gen.in", "ind.in",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.nz", "co.za",
    "com.br", "com.sg", "com.my", "com.hk",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "t.ly", "bl.ink", "lnkd.in",
}

# TLDs disproportionately abused for phishing / throwaway domains.
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga",
    "work", "support", "live", "rest", "fit", "loan", "review", "kim", "cam",
}

SENSITIVE_PATH_WORDS = {
    "login", "signin", "verify", "secure", "account", "password", "passwd",
    "payment", "pay", "offer", "offer-letter", "kyc", "update", "confirm", "wallet",
}

# Schemes that execute content rather than navigate to a page. Never legitimate
# in a job link, and urlsplit() cannot meaningfully parse them.
DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file", "blob", "about"}

# Executable/installer extensions that should never be the target of a "job offer".
EXECUTABLE_EXTS = (
    ".exe", ".scr", ".apk", ".msi", ".bat", ".cmd", ".com", ".jar", ".vbs",
    ".ps1", ".hta", ".iso", ".dmg", ".pif",
)

SAFE_BAND = "NONE"


# --- scoring vocabulary -----------------------------------------------------
def _band(score: int) -> str:
    return ("CRITICAL" if score >= 75 else "HIGH" if score >= 50
            else "MEDIUM" if score >= 25 else "LOW" if score > 0 else "NONE")


def _verdict(score: int) -> str:
    return "DANGEROUS" if score >= 50 else "SUSPICIOUS" if score >= 25 else "SAFE"


@dataclass
class Signal:
    name: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    weight: int
    detail: str

    def to_dict(self) -> dict:
        return {"name": self.name, "severity": self.severity,
                "weight": self.weight, "detail": self.detail}


@dataclass
class UrlVerdict:
    url: str
    host: str = ""
    registrable_domain: str = ""
    scheme: str = ""
    is_https: bool = False
    brand_impersonation: bool = False
    matches_official: bool = False
    risk_score: int = 0
    risk_band: str = "NONE"
    verdict: str = "SAFE"
    ml_probability: Optional[float] = None   # None when no trained model is loaded
    signals: List[Signal] = field(default_factory=list)
    advice: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url, "host": self.host,
            "registrable_domain": self.registrable_domain,
            "scheme": self.scheme, "is_https": self.is_https,
            "brand_impersonation": self.brand_impersonation,
            "matches_official": self.matches_official,
            "risk_score": self.risk_score, "risk_band": self.risk_band,
            "verdict": self.verdict, "ml_probability": self.ml_probability,
            "advice": self.advice,
            "signals": [s.to_dict() for s in self.signals],
        }


# --- helpers ----------------------------------------------------------------
def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def registrable_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in MULTI_SUFFIX:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_ip_literal(host: str) -> bool:
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return ":" in host                       # IPv6 literal


def _has_word(haystack: str, word: str) -> bool:
    """Substring match bounded by non-alphanumerics, so 'account' misses 'accounting'."""
    return re.search(rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])", haystack) is not None


def _sld(domain: str) -> str:
    """Second-level label, e.g. 'jmdcareermaker' from 'jmdcareermaker.com'."""
    return domain.split(".")[0] if domain else ""


# --- main entry point -------------------------------------------------------
def analyze_url(url: str, brand_domains: Optional[tuple] = None,
                use_model: bool = True) -> UrlVerdict:
    brands = tuple(brand_domains or BRAND_DOMAINS)
    raw = (url or "").strip()
    v = UrlVerdict(url=raw)
    if not raw:
        v.signals.append(Signal("empty_url", "INFO", 0, "No URL supplied."))
        v.advice = ["Provide a URL to analyse."]
        return v

    # Pseudo-schemes carry executable content rather than a destination; they have
    # no host to analyse, so they are judged on the scheme alone and short-circuit.
    scheme_prefix = raw.split(":", 1)[0].lower() if ":" in raw else ""
    if scheme_prefix in DANGEROUS_SCHEMES:
        v.scheme = scheme_prefix
        v.signals.append(Signal(
            "dangerous_scheme", "CRITICAL", 60,
            f"'{scheme_prefix}:' links execute content instead of opening a page — "
            f"never click one sent by e-mail."))
        v.risk_score, v.risk_band, v.verdict = 60, _band(60), _verdict(60)
        v.advice = [f"Do NOT click. A '{scheme_prefix}:' link runs code in your browser.",
                    "Report it to the security team — this is not a normal web link."]
        return v

    # Many pasted links omit the scheme; record that, then parse with a stand-in.
    had_scheme = "://" in raw
    try:
        parsed = urlsplit(raw if had_scheme else "http://" + raw)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port                      # property: raises on a malformed port
    except ValueError as e:
        v.signals.append(Signal("malformed_url", "HIGH", 35,
                                f"URL could not be parsed ({e}) — malformed or deliberately obfuscated."))
        v.risk_score, v.risk_band, v.verdict = 35, _band(35), _verdict(35)
        v.advice = ["Malformed link — do not click. Ask the sender to resend it in plain text."]
        return v

    v.scheme = parsed.scheme if had_scheme else ""
    # A pasted link with no scheme is not evidence of an insecure site — the user
    # simply didn't type "https://". Only an explicit http:// counts against it.
    v.is_https = parsed.scheme == "https"
    explicit_insecure = had_scheme and parsed.scheme == "http"
    v.host = host
    if not host:
        v.signals.append(Signal("unparseable", "HIGH", 30, "Could not extract a host from the URL."))
        v.risk_score, v.risk_band, v.verdict = 30, _band(30), _verdict(30)
        v.advice = ["Malformed link — do not click. Ask the sender to resend it in plain text."]
        return v

    reg = registrable_domain(host)
    v.registrable_domain = reg
    sigs: List[Signal] = []

    # 0. Exact official-domain match short-circuits brand checks.
    brand_regs = {registrable_domain(b.lower()) for b in brands}
    brand_slds = {_sld(b.lower()) for b in brands}
    v.matches_official = reg in brand_regs

    # 1. Credential / userinfo trap:  https://jmdcareermaker.com@evil.ru/
    if parsed.username or "@" in (parsed.netloc or ""):
        sigs.append(Signal("userinfo_trap", "CRITICAL", 35,
                           f"Real destination is '{host}', hidden after an '@'. Classic disguise."))

    # 2. IP-literal host.
    if _is_ip_literal(host):
        sigs.append(Signal("ip_host", "HIGH", 30,
                           "Host is a raw IP address — legitimate brands use named domains."))

    # 3. URL shortener (destination concealed).
    if reg in URL_SHORTENERS:
        sigs.append(Signal("url_shortener", "HIGH", 25,
                           f"'{reg}' is a link shortener; the true destination is hidden. Expand before trusting."))

    # 4. Punycode / homograph.
    if "xn--" in host:
        sigs.append(Signal("punycode_homograph", "HIGH", 30,
                           "Host uses punycode (xn--), often a homograph that mimics real letters."))

    # 4b. Raw (non-punycode) non-ASCII in the host — a homoglyph the browser will
    #     display as ordinary Latin text. Punycode is caught above; this catches the
    #     form that arrives already decoded.
    if any(ord(c) > 127 for c in host):
        confusables = "".join(sorted({c for c in host if ord(c) > 127}))
        sigs.append(Signal("unicode_homoglyph", "CRITICAL", 40,
                           f"Host contains non-Latin character(s) '{confusables}' that render like "
                           f"ordinary letters — a homograph attack."))

    # 5. Brand impersonation (only when it is NOT the genuine domain).
    if not v.matches_official:
        cand_sld = _sld(reg)
        cand_compact = "".join(c for c in cand_sld if c.isalnum())   # ignore hyphens/dots
        impersonates = False
        for b_reg, b_sld in zip(sorted(brand_regs), sorted(brand_slds)):
            d_reg = levenshtein(reg, b_reg)
            d_sld = levenshtein(cand_sld, b_sld)
            host_labels = host.split(".")
            if b_sld in host_labels and reg not in brand_regs:
                sigs.append(Signal("brand_in_subdomain", "CRITICAL", 40,
                                   f"'{b_sld}' appears in the host but the real domain is '{reg}', not the firm's."))
                impersonates = True
            elif 1 <= d_sld <= 3 or 1 <= d_reg <= 3:
                sigs.append(Signal("brand_typosquat", "CRITICAL", 45,
                                   f"'{reg}' is {min(d_sld, d_reg)} edit(s) from the official '{b_reg}' — a lookalike."))
                impersonates = True
            elif b_sld in cand_compact and cand_compact != b_sld:
                sigs.append(Signal("brand_lookalike", "HIGH", 35,
                                   f"Host embeds the brand name '{b_sld}' inside a different domain '{reg}'."))
                impersonates = True
        v.brand_impersonation = impersonates

    # 6. Suspicious TLD.
    tld = reg.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        sigs.append(Signal("suspicious_tld", "MEDIUM", 15,
                           f"'.{tld}' is a TLD frequently used for throwaway phishing domains."))

    # 7. Excessive subdomains (label stuffing).
    sub_labels = host[: -len(reg)].rstrip(".") if host.endswith(reg) else host
    depth = len([x for x in sub_labels.split(".") if x]) if sub_labels else 0
    if depth >= 3:
        sigs.append(Signal("excessive_subdomains", "MEDIUM", 12,
                           f"{depth} sub-domain levels — a common way to bury a malicious host."))

    # 8. Lots of hyphens / digits in the host.
    digits = sum(c.isdigit() for c in host)
    hyphens = host.count("-")
    if hyphens >= 3 or digits >= 6:
        sigs.append(Signal("noisy_host", "LOW", 10,
                           f"Host has {hyphens} hyphen(s) and {digits} digit(s) — auto-generated look."))

    # 9. Explicit http:// only. A pasted "example.com/x" with no scheme is not
    #    evidence of an insecure site, so it must not be penalised here.
    if explicit_insecure:
        sigs.append(Signal("no_https", "MEDIUM", 12,
                           "Link is not HTTPS — traffic can be read or tampered with in transit."))

    # 10. Non-standard port.
    if port and port not in (80, 443):
        sigs.append(Signal("non_standard_port", "MEDIUM", 12,
                           f"Connects on unusual port {port} instead of 80/443."))

    # 11. Sensitive keywords in the path/query, matched on word boundaries so
    #     "/accounting" and "/updates" don't masquerade as "account"/"update".
    #     The firm's own site legitimately has /login and /account pages, so this
    #     only counts against a domain that is not the genuine one.
    path_q = f"{parsed.path}?{parsed.query}".lower()
    hits = sorted({w for w in SENSITIVE_PATH_WORDS if _has_word(path_q, w)})
    if hits and not v.matches_official:
        sigs.append(Signal("sensitive_path", "MEDIUM", 12,
                           f"Path requests sensitive actions ({', '.join(hits)}) — common in credential-harvest pages."))

    # 11b. Executable payload disguised as a document.
    path_l = parsed.path.lower()
    if path_l.endswith(EXECUTABLE_EXTS):
        double = any(f"{doc}{exe}" in path_l
                     for doc in (".pdf", ".doc", ".docx", ".jpg", ".png", ".zip")
                     for exe in EXECUTABLE_EXTS)
        sigs.append(Signal(
            "executable_download", "CRITICAL" if double else "HIGH", 40 if double else 30,
            "Link downloads an executable"
            + (" disguised with a double extension." if double else " rather than opening a page.")))

    # 12. Credentials leaked in the query string.
    if any(k in parsed.query.lower() for k in ("password=", "passwd=", "token=", "secret=")):
        sigs.append(Signal("secret_in_query", "MEDIUM", 12,
                           "A secret/token is exposed in the query string of the link."))

    # Learned signal: a trained ML classifier scores the URL holistically. It is
    # skipped for the genuine domain so a real link is never penalised, and only
    # contributes when it is reasonably confident the link is malicious.
    if use_model and not v.matches_official:
        m = _model()
        if m is not None:
            prob = m.predict_proba(raw)
            v.ml_probability = round(float(prob), 4)
            if prob >= ML_THRESHOLD:
                sigs.append(Signal(
                    "ml_phishing_pattern", "HIGH" if prob >= 0.8 else "MEDIUM",
                    int(round(prob * 30)),
                    f"ML model rates this link {prob:.0%} likely malicious from learned URL patterns."))

    # Official domain with no other issues → reassure explicitly.
    if v.matches_official and not sigs:
        sigs.append(Signal("matches_official", "INFO", 0,
                           f"'{reg}' is the firm's genuine domain."))

    score = min(100, sum(s.weight for s in sigs))
    v.signals = sorted(sigs, key=lambda s: s.weight, reverse=True)
    v.risk_score = score
    v.risk_band = _band(score)
    v.verdict = _verdict(score)
    v.advice = _advice(v)
    return v


# Public API (mirrors the other tools: a primary verb + a batch `scan`).
def analyze(url: str, brand_domains: Optional[tuple] = None) -> UrlVerdict:
    return analyze_url(url, brand_domains)


def scan(urls: List[str], brand_domains: Optional[tuple] = None) -> List[UrlVerdict]:
    """Analyse many links, most dangerous first."""
    return sorted((analyze_url(u, brand_domains) for u in urls),
                  key=lambda v: v.risk_score, reverse=True)


def _advice(v: UrlVerdict) -> List[str]:
    if v.matches_official and v.risk_score < 25:
        return ["Domain matches the firm's official site — safe to use."
                + ("" if v.is_https else " Prefer the https:// version.")]
    if v.verdict == "SAFE":
        return ["No strong red flags, but verify the sender before entering any credentials."]
    a: List[str] = []
    if v.brand_impersonation:
        a.append("Do NOT enter credentials — this lookalike domain is impersonating the firm.")
    if any(s.name == "url_shortener" for s in v.signals):
        a.append("Expand the shortened link (e.g. preview it) before clicking.")
    if any(s.name == "userinfo_trap" for s in v.signals):
        a.append(f"The link actually goes to '{v.host}', not where it appears to. Block it.")
    a.append("Report this link to the security team and warn the candidate who received it."
             if v.verdict == "DANGEROUS"
             else "Treat with caution and confirm the link through a known-good channel.")
    return a


if __name__ == "__main__":
    for u in ("https://jmdcareermaker.com/careers",
              "http://bit.ly/jmd-offer",
              "https://jmdcaremaker.com/login",
              "https://jmdcareermaker.com.secure-login.ru/verify",
              "http://jmdcareermaker.com@192.168.0.5/pay"):
        r = analyze_url(u)
        print(f"{r.verdict:10} {r.risk_band:8} score={r.risk_score:3}  {u}")
