import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from resumeshield.pii import detect, verhoeff_ok, luhn_ok  # noqa: E402
from resumeshield.redact import redact  # noqa: E402

VALID_AADHAAR = "299418556015"
INVALID_AADHAAR = "299418556014"  # valid Aadhaar with a wrong final check digit
VISA_TEST = "4111111111111111"  # Luhn-valid test card


def _types(text):
    return {m.type for m in detect(text)}


def test_email_phone():
    t = _types("reach me at a.b@example.com or +91 98765 43210")
    assert "EMAIL" in t and "PHONE" in t


def test_aadhaar_checksum():
    assert verhoeff_ok(VALID_AADHAAR)
    assert not verhoeff_ok(INVALID_AADHAAR)
    assert "AADHAAR" in _types(f"Aadhaar {VALID_AADHAAR[:4]} {VALID_AADHAAR[4:8]} {VALID_AADHAAR[8:]}")
    assert "AADHAAR" not in _types(f"ref number {INVALID_AADHAAR}")


def test_pan_and_card():
    assert "PAN" in _types("PAN: ABCDE1234F")
    assert luhn_ok(VISA_TEST)
    assert "CREDIT_CARD" in _types(f"card {VISA_TEST}")


def test_bank_account_requires_context():
    assert "BANK_ACCOUNT" in _types("A/c 123456789012")
    # a bare long number with no a/c context should not be flagged as a bank account
    assert "BANK_ACCOUNT" not in _types("order id 998877665544")


def test_redaction_removes_values():
    txt = "Email me at secret.person@mail.com"
    r = redact(txt)
    assert "secret.person@mail.com" not in r.redacted_text
    assert "[REDACTED:EMAIL]" in r.redacted_text


def test_risk_and_dpdp():
    txt = f"PAN ABCDE1234F Aadhaar {VALID_AADHAAR} A/c 123456789012"
    r = redact(txt)
    assert r.risk_band in {"HIGH", "CRITICAL"}
    assert not r.dpdp["compliant_to_share_as_is"]
    assert "AADHAAR" in r.dpdp["sensitive_identifiers_present"]


def test_clean_text_is_compliant():
    r = redact("Experienced engineer skilled in Python and security.")
    assert r.risk_score == 0
    assert r.dpdp["compliant_to_share_as_is"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"  ✓ {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed.")
