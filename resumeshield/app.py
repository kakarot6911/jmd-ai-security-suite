"""ResumeShield dashboard.  Run: streamlit run resumeshield/app.py"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from resumeshield.redact import redact  # noqa: E402

st.set_page_config(page_title="ResumeShield · JMD", page_icon="🪪", layout="wide")
BAND_COLOR = {"CRITICAL": "#b00020", "HIGH": "#e65100", "MEDIUM": "#f9a825", "LOW": "#2e7d32"}

SAMPLE = (
    "Name: Fazal Ahmad\nEmail: fazal.ahmad@example.com   Phone: +91 98765 43210\n"
    "Aadhaar: 2994 1855 6015    PAN: ABCDE1234F\n"
    "A/c 123456789012 (HDFC Bank)   DOB: 23/08/2001\n"
    "Address: Tower 28, Lodha Belmondo, Pune 411045\n"
    "LinkedIn: https://linkedin.com/in/fazal-ahmad"
)


def read_pdf(file) -> str:
    from pypdf import PdfReader
    return "\n".join((p.extract_text() or "") for p in PdfReader(file).pages)


st.title("🪪 ResumeShield")
st.caption("Candidate PII redaction & DPDP Act 2023 compliance · JMD The Career Maker")

with st.sidebar:
    keep_last = st.slider("Reveal last N chars (0 = full redaction)", 0, 4, 0)
    st.markdown("---")
    st.caption("Protects candidate data before resumes are shared with employer clients. "
               "Detects Aadhaar (checksum-validated), PAN, cards (Luhn), bank a/c, contact & ID data.")

up = st.file_uploader("Upload resume (.txt or .pdf)", type=["txt", "pdf"])
default = SAMPLE if up is None else ""
if up is not None:
    text = read_pdf(up) if up.name.lower().endswith(".pdf") else up.read().decode("utf-8", "ignore")
else:
    text = st.text_area("…or paste resume text", value=default, height=240)

if st.button("🛡️ Scan & redact", type="primary", use_container_width=True):
    if not text.strip():
        st.warning("Provide some text or a file.")
        st.stop()
    r = redact(text, keep_last=keep_last)
    color = BAND_COLOR[r.risk_band]
    c1, c2, c3 = st.columns([1.2, 1, 1])
    c1.markdown(
        f"<div style='padding:16px;border-radius:12px;background:{color};color:white'>"
        f"<div style='font-size:12px;opacity:.85'>EXPOSURE RISK</div>"
        f"<div style='font-size:30px;font-weight:700'>{r.risk_band}</div>"
        f"<div>{r.risk_score}/100</div></div>", unsafe_allow_html=True)
    c2.metric("PII items found", sum(r.inventory.values()))
    c3.metric("Safe to share as-is", "YES" if r.dpdp["compliant_to_share_as_is"] else "NO")

    left, right = st.columns(2)
    with left:
        st.subheader("Redacted resume")
        st.text_area("redacted", r.redacted_text, height=300, label_visibility="collapsed")
        st.download_button("⬇️ Download redacted text", r.redacted_text,
                           "resume_redacted.txt", "text/plain")
    with right:
        st.subheader("PII inventory")
        st.dataframe(pd.DataFrame(
            [{"type": k, "count": v} for k, v in r.inventory.items()]),
            hide_index=True, use_container_width=True)
        st.subheader("DPDP compliance report")
        st.json(r.dpdp)
