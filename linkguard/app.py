"""LinkGuard dashboard.  Run: streamlit run linkguard/app.py"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from linkguard.demo import DEMOS  # noqa: E402
from linkguard.engine import analyze_url  # noqa: E402

st.set_page_config(page_title="LinkGuard · JMD", page_icon="🔗", layout="wide")
BAND_COLOR = {"CRITICAL": "#b00020", "HIGH": "#e65100", "MEDIUM": "#f9a825",
              "LOW": "#2e7d32", "NONE": "#2e7d32"}

st.title("🔗 LinkGuard")
st.caption("URL safety analyzer — spots typosquats, shorteners & impersonation · JMD The Career Maker")

choice = st.selectbox("Try a sample link", ["— type my own —", *DEMOS])
default = DEMOS.get(choice, "")
url = st.text_input("URL", value=default, placeholder="https://jmdcareermaker.com/careers")

if st.button("▶️ Analyze link", type="primary") and url:
    v = analyze_url(url)
    color = BAND_COLOR.get(v.risk_band, "#555")
    c1, c2, c3 = st.columns([1, 1, 2])
    c1.markdown(
        f"<div style='padding:18px;border-radius:12px;background:{color};color:white;text-align:center'>"
        f"<div style='font-size:12px;opacity:.85'>VERDICT</div>"
        f"<div style='font-size:34px;font-weight:800'>{v.verdict}</div></div>",
        unsafe_allow_html=True)
    c2.metric("Risk score", f"{v.risk_score}/100")
    c3.metric("Real destination", v.registrable_domain or "—",
              "official" if v.matches_official else "impersonation" if v.brand_impersonation else "")

    if v.signals:
        st.subheader("Signals")
        st.dataframe(pd.DataFrame([
            {"severity": s.severity, "signal": s.name, "weight": s.weight, "why": s.detail}
            for s in v.signals if s.weight or s.severity == "INFO"]),
            hide_index=True, use_container_width=True)
    st.subheader("Recommended action")
    for a in v.advice:
        st.write("• " + a)
