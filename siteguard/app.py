"""SiteGuard dashboard.  Run: streamlit run siteguard/app.py"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from siteguard.demo import DEMOS  # noqa: E402
from siteguard.scanner import scan  # noqa: E402

st.set_page_config(page_title="SiteGuard · JMD", page_icon="🔐", layout="wide")
GRADE_COLOR = {"A": "#2e7d32", "B": "#558b2f", "C": "#f9a825", "D": "#e65100", "F": "#b00020"}

st.title("🔐 SiteGuard")
st.caption("Passive web security-posture scanner · JMD The Career Maker")

mode = st.radio("Mode", ["Offline demo", "Live scan (authorized)"], horizontal=True)

res = None
if mode == "Offline demo":
    target = st.selectbox("Demo target", list(DEMOS))
    if st.button("▶️ Run demo scan", type="primary"):
        res = scan(f"https://{target}.demo", authorized=True, fetcher=DEMOS[target])
else:
    url = st.text_input("Target URL", placeholder="https://www.jmdcareermaker.com")
    ok = st.checkbox("I confirm I own this domain or am authorized to test it.")
    st.caption("SiteGuard only performs safe, non-intrusive GET requests.")
    if st.button("▶️ Run live scan", type="primary"):
        if not url or not ok:
            st.warning("Enter a URL and confirm authorization.")
        else:
            with st.spinner("Scanning…"):
                res = scan(url, authorized=True)

if res is not None:
    color = GRADE_COLOR.get(res.grade, "#555")
    c1, c2, c3 = st.columns([1, 1, 2])
    c1.markdown(
        f"<div style='padding:18px;border-radius:12px;background:{color};color:white;text-align:center'>"
        f"<div style='font-size:12px;opacity:.85'>GRADE</div>"
        f"<div style='font-size:46px;font-weight:800'>{res.grade}</div></div>",
        unsafe_allow_html=True)
    c2.metric("Posture score", f"{res.posture_score}/100")
    c3.metric("Findings", len(res.findings))

    if res.findings:
        st.subheader("Findings")
        st.dataframe(pd.DataFrame([
            {"severity": f.severity, "title": f.title, "category": f.category,
             "remediation": f.remediation} for f in res.findings]),
            hide_index=True, use_container_width=True)
    else:
        st.success("No issues found — solid posture.")
    if res.info:
        st.subheader("Target info")
        st.json({k: v for k, v in res.info.items() if k != "target"})
