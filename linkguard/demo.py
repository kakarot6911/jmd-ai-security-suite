"""Curated sample links so LinkGuard demos (and the UI) work fully offline."""
from __future__ import annotations

# label -> URL.  A spread from clearly safe to clearly dangerous.
DEMOS = {
    "Official careers page": "https://jmdcareermaker.com/careers/ai-cybersecurity-intern",
    "Shortened offer link": "http://bit.ly/jmd-offer",
    "Typosquat login": "https://jmdcaremaker.com/login",
    "Brand buried in subdomain": "https://jmdcareermaker.com.secure-login.ru/verify",
    "Credential @-trap": "http://jmdcareermaker.com@192.168.0.5/pay?token=abc123",
    "Punycode homograph": "https://xn--jmdcareermker-9zb.com/account",
    "Hyphen lookalike + .xyz": "http://jmd-careermaker-hr.xyz/offer-letter",
}
