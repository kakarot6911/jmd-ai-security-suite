"""
LinkGuard CLI — offline URL safety analysis.

  Check one link:    python -m linkguard.cli check "http://bit.ly/jmd-offer"
  Scan a file:       python -m linkguard.cli scan-file links.txt
  Run the samples:   python -m linkguard.cli demo
"""
from __future__ import annotations

import argparse
import json

from .demo import DEMOS
from .engine import analyze_url

_ICON = {"DANGEROUS": "⛔", "SUSPICIOUS": "⚠️ ", "SAFE": "✓ "}


def _print(v) -> None:
    print(f"{_ICON.get(v.verdict, '?')}{v.verdict:10} {v.risk_band:8} "
          f"score={v.risk_score:3}  {v.host or v.url}")
    for s in v.signals:
        if s.weight:
            print(f"      · [{s.severity:8}] {s.name}: {s.detail}")


def main() -> None:
    ap = argparse.ArgumentParser(description="LinkGuard — URL safety analyzer (offline).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check"); c.add_argument("url")
    f = sub.add_parser("scan-file"); f.add_argument("path")
    sub.add_parser("demo")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if args.cmd == "check":
        res = [analyze_url(args.url)]
    elif args.cmd == "demo":
        res = [analyze_url(u) for u in DEMOS.values()]
    else:
        urls = [ln.strip() for ln in open(args.path) if ln.strip()]
        res = [analyze_url(u) for u in urls]

    if args.json:
        print(json.dumps([v.to_dict() for v in res], indent=2)); return

    for v in res:
        _print(v)
    if len(res) > 1:
        danger = sum(1 for v in res if v.verdict == "DANGEROUS")
        susp = sum(1 for v in res if v.verdict == "SUSPICIOUS")
        print(f"\nSummary: {len(res)} links · {danger} dangerous · {susp} suspicious")


if __name__ == "__main__":
    main()
