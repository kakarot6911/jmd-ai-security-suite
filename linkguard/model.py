"""
LinkGuard ML — a *trained* phishing-URL classifier.

This is the genuine machine-learning component of LinkGuard (companion to
PhishGuard's text model). It learns to tell malicious links from benign ones from
two complementary views of a URL:

  1. **Character n-grams** (`char_wb` TF-IDF) — captures the raw look of the string
     (odd tokens, hyphen/digit soup, brand fragments) the way PhishGuard reads words.
  2. **Lexical features** — the structured signals from `engine.analyze_url`
     (typosquat distance, brand impersonation, IP host, shortener, TLD, depth, …),
     so the model also reasons over hand-engineered security knowledge.

A `LogisticRegression` head fuses both into a calibrated probability. Training data
is **synthetic and seeded** (reproducible, offline) — benign links from real-shaped
domains, malicious links generated with the actual phishing tricks LinkGuard targets.

  Train:   python -m linkguard.model            (writes models/url_model.joblib)
  Reuse:   from linkguard.model import load_model
"""
from __future__ import annotations

import functools
import json
import random
from pathlib import Path
from typing import List, Tuple

MODEL_DIR = Path(__file__).resolve().parent / "models"
MODEL_PATH = MODEL_DIR / "url_model.joblib"
METRICS_PATH = MODEL_DIR / "metrics.json"

# Domains/brands the synthetic generator treats as legitimate.
BENIGN_DOMAINS = [
    "jmdcareermaker.com", "google.com", "microsoft.com", "github.com",
    "linkedin.com", "naukri.com", "indeed.com", "monster.com", "shine.com",
    "timesjobs.com", "wikipedia.org", "amazon.in", "flipkart.com", "zoho.com",
    "freshersworld.com", "glassdoor.co.in", "apna.co", "instahyre.com",
]
BENIGN_PATHS = [
    "", "/", "/careers", "/jobs", "/jobs/12345", "/about", "/contact",
    "/careers/ai-cybersecurity-intern", "/login", "/account", "/help",
    "/blog/how-to-apply", "/companies/abc", "/search?q=intern", "/profile",
]
BRANDS_TO_SPOOF = ["jmdcareermaker", "linkedin", "naukri", "indeed", "microsoft"]
EVIL_TLDS = ["xyz", "top", "click", "zip", "online", "live", "support", "tk", "ml", "info", "ru", "cn"]
EVIL_HOSTS = ["secure-login", "verify-account", "hr-portal", "offer-claim", "payment-update"]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"]
SENSITIVE_PATHS = ["/login", "/verify", "/account/confirm", "/offer-letter", "/kyc",
                   "/payment", "/secure/update", "/wallet", "/reset-password"]


def _rand_ip(rng: random.Random) -> str:
    return ".".join(str(rng.randint(1, 254)) for _ in range(4))


def _typo(rng: random.Random, s: str) -> str:
    """One small edit — drop, duplicate or swap a character (a typosquat)."""
    if len(s) < 4:
        return s + rng.choice("aeiou")
    i = rng.randrange(len(s))
    op = rng.choice(("drop", "dup", "swap"))
    if op == "drop":
        return s[:i] + s[i + 1:]
    if op == "dup":
        return s[:i] + s[i] + s[i:]
    j = min(i + 1, len(s) - 1)
    return s[:i] + s[j] + s[i] + s[j + 1:]


def _benign(rng: random.Random) -> str:
    dom = rng.choice(BENIGN_DOMAINS)
    path = rng.choice(BENIGN_PATHS)
    scheme = "https" if rng.random() < 0.9 else "http"
    sub = rng.choice(["", "", "", "www.", "jobs.", "careers."])
    return f"{scheme}://{sub}{dom}{path}"


def _malicious(rng: random.Random) -> str:
    kind = rng.choice(["typosquat", "subdomain", "userinfo", "shortener",
                        "punycode", "iphost", "hyphen_tld"])
    brand = rng.choice(BRANDS_TO_SPOOF)
    path = rng.choice(SENSITIVE_PATHS)
    if kind == "typosquat":
        return f"http://{_typo(rng, brand)}.{rng.choice(EVIL_TLDS)}{path}"
    if kind == "subdomain":
        return f"http://{brand}.com.{rng.choice(EVIL_HOSTS)}.{rng.choice(EVIL_TLDS)}{path}"
    if kind == "userinfo":
        tail = _rand_ip(rng) if rng.random() < 0.5 else f"{rng.choice(EVIL_HOSTS)}.{rng.choice(EVIL_TLDS)}"
        return f"http://{brand}.com@{tail}{path}"
    if kind == "shortener":
        return f"http://{rng.choice(SHORTENERS)}/{''.join(rng.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=6))}"
    if kind == "punycode":
        return f"http://xn--{brand[:6]}{rng.randint(10, 99)}-{rng.choice('abcdefg')}zb.com{path}"
    if kind == "iphost":
        return f"http://{_rand_ip(rng)}{path}?token={''.join(rng.choices('abcdef0123456789', k=8))}"
    return f"http://{brand}-{rng.choice(EVIL_HOSTS)}.{rng.choice(EVIL_TLDS)}{path}"


def make_dataset(n_per_class: int = 1500, seed: int = 42) -> Tuple[List[str], List[int]]:
    """Reproducible synthetic corpus: label 1 = malicious, 0 = benign."""
    rng = random.Random(seed)
    urls, labels = [], []
    for _ in range(n_per_class):
        urls.append(_benign(rng)); labels.append(0)
        urls.append(_malicious(rng)); labels.append(1)
    idx = list(range(len(urls)))
    rng.shuffle(idx)
    return [urls[i] for i in idx], [labels[i] for i in idx]


# --- features ---------------------------------------------------------------
# Top-level (picklable) so the saved pipeline can reload them.
def url_to_features(url: str) -> dict:
    """Structured lexical features, derived from the heuristic engine (no ML)."""
    from linkguard.engine import analyze_url  # local import avoids a cycle
    v = analyze_url(url, use_model=False)
    names = {s.name for s in v.signals}
    host = v.host
    return {
        "heur_score": v.risk_score,
        "is_https": int(v.is_https),
        "brand_impersonation": int(v.brand_impersonation),
        "matches_official": int(v.matches_official),
        "host_len": len(host),
        "n_dots": host.count("."),
        "n_hyphens": host.count("-"),
        "n_digits": sum(c.isdigit() for c in host),
        "has_at": int("@" in url),
        "sig_typosquat": int("brand_typosquat" in names),
        "sig_subdomain": int("brand_in_subdomain" in names),
        "sig_userinfo": int("userinfo_trap" in names),
        "sig_shortener": int("url_shortener" in names),
        "sig_punycode": int("punycode_homograph" in names),
        "sig_ip": int("ip_host" in names),
        "sig_susp_tld": int("suspicious_tld" in names),
        "sig_sensitive": int("sensitive_path" in names),
    }


def feature_dicts(urls: List[str]) -> List[dict]:
    return [url_to_features(u) for u in urls]


def _build_pipeline():
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import FeatureUnion, Pipeline
    from sklearn.preprocessing import FunctionTransformer

    chars = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, lowercase=True)
    lex = Pipeline([
        ("extract", FunctionTransformer(feature_dicts)),
        ("vec", DictVectorizer(sparse=True)),
    ])
    feats = FeatureUnion([("chars", chars), ("lex", lex)])
    return Pipeline([
        ("features", feats),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", C=4.0)),
    ])


class URLClassifier:
    """Thin wrapper so callers get a stable `.predict_proba(url) -> float`."""
    def __init__(self, pipeline):
        self.pipeline = pipeline

    def predict_proba(self, url: str) -> float:
        return float(self.pipeline.predict_proba([url])[0][1])


def train(n_per_class: int = 1500, seed: int = 42, save: bool = True) -> dict:
    import joblib
    from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                                 precision_score, recall_score, roc_auc_score)
    from sklearn.model_selection import train_test_split

    urls, labels = make_dataset(n_per_class, seed)
    Xtr, Xte, ytr, yte = train_test_split(urls, labels, test_size=0.25,
                                          random_state=seed, stratify=labels)
    pipe = _build_pipeline()
    pipe.fit(Xtr, ytr)

    proba = pipe.predict_proba(Xte)[:, 1]
    pred = (proba >= 0.5).astype(int)
    metrics = {
        "samples": len(urls), "train": len(Xtr), "test": len(Xte),
        "accuracy": round(accuracy_score(yte, pred), 4),
        "precision": round(precision_score(yte, pred), 4),
        "recall": round(recall_score(yte, pred), 4),
        "f1": round(f1_score(yte, pred), 4),
        "roc_auc": round(roc_auc_score(yte, proba), 4),
        "confusion_matrix": confusion_matrix(yte, pred).tolist(),
        "seed": seed,
    }
    if save:
        MODEL_DIR.mkdir(exist_ok=True)
        joblib.dump(URLClassifier(pipe), MODEL_PATH)
        METRICS_PATH.write_text(json.dumps(metrics, indent=2))
    return metrics


@functools.lru_cache(maxsize=1)
def load_model():
    """Return the trained URLClassifier, or None if it hasn't been trained yet."""
    if not MODEL_PATH.exists():
        return None
    import joblib
    return joblib.load(MODEL_PATH)


if __name__ == "__main__":
    m = train()
    print("LinkGuard URL model trained:")
    for k in ("samples", "train", "test", "accuracy", "precision", "recall", "f1", "roc_auc"):
        print(f"  {k:10} {m[k]}")
    print(f"  confusion  {m['confusion_matrix']}  [[TN,FP],[FN,TP]]")
    print(f"  saved → {MODEL_PATH}")
