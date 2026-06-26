"""
SiteGuard CLI.

  Offline demo:  python -m siteguard.cli --demo vulnerable
  Live scan:     python -m siteguard.cli https://yourdomain.com --authorize

Only pass --authorize for domains you own or are explicitly permitted to test.
"""
from __future__ import annotations

import argparse
import json

from .demo import DEMOS
from .scanner import scan


def main():
    ap = argparse.ArgumentParser(description="Passive web security-posture scanner.")
    ap.add_argument("url", nargs="?", help="target URL (live mode)")
    ap.add_argument("--demo", choices=list(DEMOS), help="run an offline demo target")
    ap.add_argument("--authorize", action="store_true",
                    help="confirm you are authorized to scan this domain")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if args.demo:
        res = scan(f"https://{args.demo}.demo", authorized=True, fetcher=DEMOS[args.demo])
    elif args.url:
        res = scan(args.url, authorized=args.authorize)
    else:
        ap.error("provide a URL (with --authorize) or --demo {hardened|vulnerable}")

    if args.json:
        print(json.dumps(res.to_dict(), indent=2))
        return

    print(f"Target : {res.target}")
    print(f"Grade  : {res.grade}   Posture score: {res.posture_score}/100")
    print(f"Findings ({len(res.findings)}):")
    for f in res.findings:
        print(f"  [{f.severity:8}] {f.title}")
        print(f"             ↳ {f.remediation}")
    if res.info:
        print("Info:", {k: v for k, v in res.info.items() if k != "target"})


if __name__ == "__main__":
    main()
