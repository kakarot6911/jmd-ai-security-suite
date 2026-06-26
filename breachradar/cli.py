"""
BreachRadar CLI.

  Check one address:   python -m breachradar.cli check hr@jmdcareermaker.com
  Scan all org emails: python -m breachradar.cli scan-org
  Scan a file:         python -m breachradar.cli scan-file emails.txt
"""
from __future__ import annotations

import argparse
import json

from .engine import BreachRadar


def _print(x):
    tag = "⚠️ " if x.breaches else "✓ "
    print(f"{tag}{x.email:34} {x.risk_band:8} score={x.risk_score:3} "
          f"breaches={len(x.breaches)} pwd={'YES' if x.password_exposed else 'no'}")


def main():
    ap = argparse.ArgumentParser(description="Credential-exposure monitor (offline corpus).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check"); c.add_argument("email")
    sub.add_parser("scan-org")
    f = sub.add_parser("scan-file"); f.add_argument("path")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    radar = BreachRadar()
    if args.cmd == "check":
        res = [radar.check(args.email)]
    elif args.cmd == "scan-org":
        res = radar.scan(radar.org_emails)
    else:
        emails = [ln.strip() for ln in open(args.path) if ln.strip()]
        res = radar.scan(emails)

    if args.json:
        print(json.dumps([x.to_dict() for x in res], indent=2)); return

    for x in res:
        _print(x)
    if len(res) > 1:
        exposed = sum(1 for x in res if x.breaches)
        crit = sum(1 for x in res if x.risk_band in {"CRITICAL", "HIGH"})
        print(f"\nSummary: {exposed}/{len(res)} exposed · {crit} at HIGH/CRITICAL risk")


if __name__ == "__main__":
    main()
