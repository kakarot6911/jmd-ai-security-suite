import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from linkguard.engine import analyze_url  # noqa: E402
from linkguard.model import (  # noqa: E402
    URLClassifier, _build_pipeline, feature_dicts, load_model, make_dataset,
    train, url_to_features,
)


def test_dataset_is_balanced_and_seeded():
    a_urls, a_labels = make_dataset(200, seed=7)
    b_urls, b_labels = make_dataset(200, seed=7)
    assert a_urls == b_urls and a_labels == b_labels          # reproducible
    assert len(a_urls) == 400
    assert sum(a_labels) == 200                                 # 50/50 split


def test_features_capture_phishing_structure():
    f = url_to_features("https://jmdcareermaker.com.secure-login.ru/verify")
    assert f["brand_impersonation"] == 1
    assert f["matches_official"] == 0
    assert set(feature_dicts(["http://bit.ly/x"])[0]) == set(f)  # stable schema


def test_model_trains_and_separates_classes():
    urls, labels = make_dataset(300, seed=3)
    clf = URLClassifier(_build_pipeline().fit(urls, labels))
    assert clf.predict_proba("http://jmdcaremaker.xyz/login") > 0.5     # malicious
    assert clf.predict_proba("https://jmdcareermaker.com/careers") < 0.5  # benign


def test_training_metrics_are_strong():
    m = train(n_per_class=300, seed=5, save=False)
    assert m["accuracy"] >= 0.9
    assert m["recall"] >= 0.9


def test_engine_fuses_committed_model_when_present():
    clf = load_model()
    if clf is None:
        print("    (no committed model — skipping fusion check)"); return
    v = analyze_url("http://login-verify.naukri-hr.xyz/kyc")     # borderline phish
    assert v.ml_probability is not None and v.ml_probability > 0.5
    assert any(s.name == "ml_phishing_pattern" for s in v.signals)
    # the official domain must never be penalised by the model
    assert analyze_url("https://jmdcareermaker.com/careers").ml_probability is None


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"  ✓ {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed.")
