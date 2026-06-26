"""ResumeShield CLI.  Usage: python -m resumeshield.cli <file.txt|file.pdf> [--keep-last 4]"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .redact import redact


def read_any(path: Path) -> str:
    if path.suffix.lower() == ".pdf":
        try:
            from pypdf import PdfReader
        except ImportError:
            sys.exit("pypdf not installed; cannot read PDF. pip install pypdf")
        return "\n".join((p.extract_text() or "") for p in PdfReader(str(path)).pages)
    return path.read_text(errors="ignore")


def main():
    ap = argparse.ArgumentParser(description="Redact PII from a resume and emit a DPDP report.")
    ap.add_argument("file")
    ap.add_argument("--keep-last", type=int, default=0, help="reveal last N chars of each value")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args()

    text = read_any(Path(args.file))
    r = redact(text, keep_last=args.keep_last)

    if args.json:
        print(json.dumps({
            "risk_score": r.risk_score, "risk_band": r.risk_band,
            "inventory": r.inventory, "dpdp": r.dpdp,
            "redacted_text": r.redacted_text,
        }, indent=2))
        return

    print(f"Risk: {r.risk_score}/100  ({r.risk_band})")
    print(f"PII found: {r.inventory}")
    print(f"Sensitive identifiers: {r.dpdp['sensitive_identifiers_present'] or 'none'}")
    print(f"Safe to share as-is: {r.dpdp['compliant_to_share_as_is']}")
    print("\n--- REDACTED ---\n" + r.redacted_text)


if __name__ == "__main__":
    main()
