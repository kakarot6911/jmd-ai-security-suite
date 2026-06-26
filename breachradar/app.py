"""BreachRadar dashboard.  Run: streamlit run breachradar/app.py"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from breachradar.engine import BreachRadar  # noqa: E402

st.set_page_config(page_title="BreachRadar · JMD", page_icon="📡", layout="wide")
BAND_COLOR = {"CRITICAL": "#b00020", "HIGH": "#e65100", "MEDIUM": "#f9a825",
              "LOW": "#2e7d32", "NONE": "#2e7d32"}


@st.cache_resource
def radar():
    return BreachRadar()


st.title("📡 BreachRadar")
st.caption("Credential-exposure monitor · JMD The Career Maker · offline corpus, "
           "privacy-preserving k-anonymity lookup")

r = radar()
tab1, tab2 = st.tabs(["Check an address", "Scan organisation"])

with tab1:
    email = st.text_input("Email address", value="akash.mishra@jmdcareermaker.com")
    if st.button("🔎 Check exposure", type="primary"):
        x = r.check(email)
        color = BAND_COLOR.get(x.risk_band, "#555")
        c1, c2, c3 = st.columns([1.2, 1, 1])
        c1.markdown(
            f"<div style='padding:16px;border-radius:12px;background:{color};color:white'>"
            f"<div style='font-size:12px;opacity:.85'>RISK</div>"
            f"<div style='font-size:30px;font-weight:700'>{x.risk_band}</div>"
            f"<div>{x.risk_score}/100</div></div>", unsafe_allow_html=True)
        c2.metric("Breaches", len(x.breaches))
        c3.metric("Password exposed", "YES" if x.password_exposed else "no")
        if x.breaches:
            st.subheader("Where it appeared")
            st.dataframe(pd.DataFrame(x.breaches), hide_index=True, use_container_width=True)
        st.subheader("Recommended actions")
        for a in x.advice:
            st.write("• " + a)

with tab2:
    st.caption("Scans the monitored JMD accounts (HR, careers, finance, founder…).")
    if st.button("📡 Scan organisation", type="primary"):
        results = r.scan(r.org_emails)
        df = pd.DataFrame([{
            "email": x.email, "risk_band": x.risk_band, "score": x.risk_score,
            "breaches": len(x.breaches), "password_exposed": x.password_exposed,
            "high_value": x.high_value_target} for x in results])
        exposed = int((df["breaches"] > 0).sum())
        crit = int(df["risk_band"].isin(["CRITICAL", "HIGH"]).sum())
        c1, c2, c3 = st.columns(3)
        c1.metric("Accounts monitored", len(df))
        c2.metric("Exposed", exposed)
        c3.metric("HIGH/CRITICAL", crit)
        st.dataframe(df, hide_index=True, use_container_width=True)
        st.download_button("⬇️ Export report", df.to_csv(index=False),
                           "breachradar_report.csv", "text/csv")
