"""
Accuracy evaluation harness for the JMD Security Suite.

Run:  ./run.sh eval        (or: python eval/run_eval.py)

Reports precision / recall / accuracy per tool against the hand-labelled cases in
eval/cases.py, and lists every individual miss so a failure is actionable rather
than just a number going down.

This is measurement, not testing: it always exits 0 unless --strict is passed.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from eval.cases import (  # noqa: E402
    LINKGUARD_CASES, PHISHGUARD_CASES, RESUMESHIELD_CASES, SITEGUARD_CASES,
)

GRADES = ["F", "D", "C", "B", "A"]


class Score:
    """Confusion-matrix accumulator with a readable report."""

    def __init__(self, name: str):
        self.name = name
        self.tp = self.fp = self.tn = self.fn = 0
        self.misses: list[str] = []

    def crash(self, label: str, exc: Exception):
        """A tool that raises has failed the case — record it loudly, don't die."""
        self.fn += 1
        self.misses.append(f"CRASH           {label}  -> {type(exc).__name__}: {exc}")

    def add(self, predicted: bool, actual: bool, label: str):
        if predicted and actual:
            self.tp += 1
        elif predicted and not actual:
            self.fp += 1
            self.misses.append(f"FALSE POSITIVE  {label}")
        elif not predicted and actual:
            self.fn += 1
            self.misses.append(f"FALSE NEGATIVE  {label}")
        else:
            self.tn += 1

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def report(self, verbose: bool = True) -> bool:
        ok = not self.misses
        mark = "✓" if ok else "✗"
        print(f"\n{mark} {self.name}")
        print(f"    accuracy {self.accuracy:6.1%}   precision {self.precision:6.1%}   "
              f"recall {self.recall:6.1%}   F1 {self.f1:6.1%}   ({self.total} cases)")
        print(f"    TP={self.tp}  FP={self.fp}  TN={self.tn}  FN={self.fn}")
        if verbose and self.misses:
            for m in self.misses:
                print(f"      · {m}")
        return ok


def eval_linkguard() -> Score:
    from linkguard.engine import analyze_url

    s = Score("LinkGuard — URL threat verdicts")
    for url, should_flag, note in LINKGUARD_CASES:
        try:
            v = analyze_url(url)
        except Exception as e:  # noqa: BLE001
            s.crash(f"{note}: {url[:64]}", e)
            continue
        flagged = v.verdict in {"SUSPICIOUS", "DANGEROUS"}
        s.add(flagged, should_flag, f"{note}: {url[:64]}  -> {v.verdict}/{v.risk_score}")
    return s


def eval_resumeshield() -> Score:
    from resumeshield.pii import detect

    s = Score("ResumeShield — PII detection")
    for text, expect_present, expect_absent, note in RESUMESHIELD_CASES:
        try:
            found = {m.type for m in detect(text)}
        except Exception as e:  # noqa: BLE001
            s.crash(f"{note}: {text[:48]!r}", e)
            continue
        for t in expect_present:
            s.add(t in found, True, f"{note}: expected {t} in {text[:48]!r}")
        for t in expect_absent:
            s.add(t in found, False, f"{note}: {t} wrongly found in {text[:48]!r}")
    return s


def eval_phishguard() -> Score:
    try:
        sys.path.insert(0, str(Path.home() / "jmd_phishguard"))
        from src.predict import analyze
    except Exception as e:  # noqa: BLE001
        print(f"\n! PhishGuard unavailable ({e}) — skipped")
        return Score("PhishGuard — unavailable")

    s = Score("PhishGuard — recruitment-fraud verdicts")
    for text, sender, company, is_scam, note in PHISHGUARD_CASES:
        try:
            r = analyze(text, sender, company)
        except Exception as e:  # noqa: BLE001
            s.crash(note, e)
            continue
        prob = r["fraud_probability"] if isinstance(r, dict) else r.fraud_probability
        flagged = prob >= 0.5
        s.add(flagged, is_scam, f"{note}  -> p={prob:.2f}")
    return s


def eval_siteguard() -> Score:
    from siteguard.scanner import analyze_headers, grade_findings

    s = Score("SiteGuard — header finding detection")
    for headers, scheme, must_fire, must_not_fire, note in SITEGUARD_CASES:
        try:
            found = {f.id for f in analyze_headers(headers, scheme)}
        except Exception as e:  # noqa: BLE001
            s.crash(note, e)
            continue
        for fid in sorted(must_fire):
            s.add(fid in found, True, f"{note}: expected finding '{fid}'")
        for fid in sorted(must_not_fire):
            s.add(fid in found, False, f"{note}: spurious finding '{fid}'")
    return s


def eval_breachradar() -> Score:
    from breachradar.engine import BreachRadar

    s = Score("BreachRadar — scoring invariants")
    radar = BreachRadar()
    results = {e: radar.check(e) for e in radar.org_emails}

    for email, x in results.items():
        names = [b["breach"] for b in x.breaches]
        dupes = len(names) != len(set(names))
        s.add(dupes, False, f"duplicate breach entries for {email}: {names}")

    scores = [x.risk_score for x in results.values()]
    exposed = [v for v in scores if v > 0]
    saturated = sum(1 for v in exposed if v >= 100)
    s.add(saturated > 1, False,
          f"{saturated} accounts saturate at 100/100 — scores cannot rank them")

    for email, x in results.items():
        worse = x.password_exposed and x.high_value_target and x.breaches
        if worse:
            lower = [e2 for e2, y in results.items()
                     if y.risk_score > x.risk_score and not y.password_exposed]
            s.add(bool(lower), False,
                  f"{email} (password leaked, high-value) ranks below {lower}")
    return s


def main() -> int:
    print("=" * 78)
    print("JMD Security Suite — accuracy evaluation")
    print("=" * 78)

    scores = [eval_phishguard(), eval_resumeshield(), eval_siteguard(),
              eval_linkguard(), eval_breachradar()]
    # Materialise every report first — all() short-circuits and would hide the rest.
    all_ok = all([s.report() for s in scores])

    graded = [s for s in scores if s.total]
    if graded:
        total = sum(s.total for s in graded)
        correct = sum(s.tp + s.tn for s in graded)
        print("\n" + "-" * 78)
        print(f"OVERALL: {correct}/{total} correct = {correct / total:6.1%}"
              f"   ({sum(s.fp for s in graded)} false positives, "
              f"{sum(s.fn for s in graded)} false negatives)")
        print("-" * 78)

    if "--strict" in sys.argv and not all_ok:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
