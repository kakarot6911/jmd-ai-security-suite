"""
JMD Security Console — unified premium dashboard for all four security tools.

Run:  streamlit run console/app.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from console import integrations as ig  # noqa: E402
from console import theme as T  # noqa: E402

st.set_page_config(page_title="JMD Security Console", page_icon="🛡️", layout="wide")
T.inject()

NAV = {
    "🏠  Overview": "home",
    "🛡️  PhishGuard": "phishguard",
    "🪪  ResumeShield": "resumeshield",
    "🔐  SiteGuard": "siteguard",
    "📡  BreachRadar": "breachradar",
}


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
def sidebar() -> str:
    with st.sidebar:
        st.markdown(
            "<div style='padding:6px 2px 14px'>"
            "<div style='font-size:1.35rem;font-weight:800;letter-spacing:-.4px'>🛡️ JMD <span "
            "style='background:linear-gradient(90deg,#818cf8,#22d3ee);-webkit-background-clip:text;"
            "-webkit-text-fill-color:transparent'>Security</span></div>"
            "<div style='color:#94a3b8;font-size:.78rem;margin-top:2px'>Unified Security Console</div>"
            "</div>", unsafe_allow_html=True)
        choice = st.radio("Navigate", list(NAV.keys()), label_visibility="collapsed")
        st.markdown("<hr style='border-color:#2a3550'>", unsafe_allow_html=True)
        online = sum(1 for t in ig.TOOLS if t["available"])
        st.markdown(
            f"<div style='font-size:.8rem;color:#94a3b8'>Modules online</div>"
            f"<div style='font-size:1.1rem;font-weight:700'>{online} / {len(ig.TOOLS)}</div>"
            "<div style='margin-top:10px'>" + "".join(
                f"<div style='font-size:.82rem;margin:3px 0'>"
                f"{'🟢' if t['available'] else '🔴'} {t['icon']} {t['name']}</div>"
                for t in ig.TOOLS) + "</div>", unsafe_allow_html=True)
    return NAV[choice]


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
def page_home():
    T.hero("Security Operations Console",
           "One pane of glass for recruitment-fraud, candidate-data protection, web "
           "posture and credential-exposure monitoring.")

    org = ig.breachradar_scan_org()
    exposed = sum(1 for x in org if x["breach_count"] > 0)
    critical = sum(1 for x in org if x["risk_band"] in {"CRITICAL", "HIGH"})

    k = st.columns(4)
    k[0].metric("Modules online", f"{sum(t['available'] for t in ig.TOOLS)} / 4")
    k[1].metric("Accounts monitored", len(org))
    k[2].metric("Exposed accounts", exposed)
    k[3].metric("HIGH / CRITICAL", critical)

    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
    cols = st.columns(2)
    for i, t in enumerate(ig.TOOLS):
        with cols[i % 2]:
            st.markdown(
                T.tool_card(t["icon"], t["name"], t["desc"],
                            "Online" if t["available"] else "Offline"),
                unsafe_allow_html=True)
            st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)

    st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
    st.markdown("##### Live exposure snapshot")
    df = pd.DataFrame([{
        "account": x["email"], "risk": x["risk_band"], "score": x["risk_score"],
        "breaches": x["breach_count"], "password_exposed": x["password_exposed"],
    } for x in org])
    st.dataframe(df, hide_index=True, use_container_width=True)
    T.footer("JMD Security Suite · PhishGuard · ResumeShield · SiteGuard · BreachRadar — "
             "synthetic data · safe by default")


def _verdict_header(band: str, value: str, cols_spec=(1.2, 1, 1)):
    return st.columns(list(cols_spec))


def page_phishguard():
    T.hero("PhishGuard", "Detect fake job offers, recruitment scams and phishing that "
           "impersonate JMD The Career Maker.", eyebrow="AI Threat Detection")
    if not ig.PHISHGUARD_AVAILABLE:
        st.error("PhishGuard model not found. Train it in ~/jmd_phishguard (python -m src.train).")
        return
    samples = {
        "— pick a sample —": ("", "", ""),
        "Scam · upfront fee": (
            "Congratulations! You are SELECTED for the AI Cybersecurity Intern role at JMD The "
            "Career Maker without any interview. Pay a refundable registration fee of Rs. 1,999 "
            "today. Limited slots, act now! http://bit.ly/jmd-offer",
            "jmd.careers.official@gmail.com", "JMD The Career Maker"),
        "Legit · interview invite": (
            "Dear Fazal Ahmad, thank you for applying to the AI Cybersecurity Intern position at "
            "JMD The Career Maker. We would like to invite you to a virtual interview. No fee is "
            "required at any stage.", "akash.mishra@jmdcareermaker.com", "JMD The Career Maker"),
    }
    s = st.selectbox("Load a sample", list(samples.keys()))
    sv = samples[s]
    c = st.columns(2)
    sender = c[0].text_input("Sender email", value=sv[1])
    company = c[1].text_input("Claimed company", value=sv[2])
    text = st.text_area("Message / job offer", value=sv[0], height=190,
                        placeholder="Paste a recruitment email or job offer…")
    if st.button("🔍  Analyze message", use_container_width=True):
        if not text.strip():
            st.warning("Paste a message first."); return
        v = ig.phishguard_analyze(text, sender, company)
        a, b, d = st.columns([1.2, 1, 1])
        a.markdown(T.big_badge(v["risk_band"], f"{v['fraud_probability']:.0%} fraud probability"),
                   unsafe_allow_html=True)
        b.metric("Recommended action", v["recommended_action"])
        d.metric("Hard block", "YES" if v["hard_block"] else "no")
        st.progress(min(max(v["fraud_probability"], 0.0), 1.0))
        st.info(v["rationale"])
        if v["flags"]:
            st.markdown("##### 🚩 Security red flags")
            st.dataframe(pd.DataFrame([{"severity": round(f["severity"], 2), "rule": f["name"],
                          "why it matters": f["description"]} for f in v["flags"]]),
                         hide_index=True, use_container_width=True)
        else:
            st.success("No deterministic red flags fired.")


def page_resumeshield():
    T.hero("ResumeShield", "Redact candidate PII and check DPDP Act 2023 compliance before a "
           "resume is shared with employer clients.", eyebrow="Data Protection")
    keep_last = st.slider("Reveal last N characters (0 = full redaction)", 0, 4, 0)
    sample = ("Name: Fazal Ahmad\nEmail: fazal.ahmad@example.com   Phone: +91 98765 43210\n"
              "Aadhaar: 2994 1855 6015    PAN: ABCDE1234F\nA/c 123456789012 (HDFC Bank)\n"
              "DOB: 23/08/2001   Address: Tower 28, Lodha Belmondo, Pune 411045")
    text = st.text_area("Resume text", value=sample, height=200)
    if st.button("🛡️  Scan & redact", use_container_width=True):
        if not text.strip():
            st.warning("Provide resume text."); return
        r = ig.resumeshield_redact(text, keep_last=keep_last)
        a, b, c = st.columns([1.2, 1, 1])
        a.markdown(T.big_badge(r["risk_band"], f"{r['risk_score']}/100 exposure"),
                   unsafe_allow_html=True)
        b.metric("PII items", sum(r["inventory"].values()))
        c.metric("Safe to share", "YES" if r["dpdp"]["compliant_to_share_as_is"] else "NO")
        left, right = st.columns(2)
        with left:
            st.markdown("##### Redacted resume")
            st.text_area("redacted", r["redacted_text"], height=260, label_visibility="collapsed")
            st.download_button("⬇️  Download redacted", r["redacted_text"],
                               "resume_redacted.txt")
        with right:
            st.markdown("##### PII inventory")
            st.dataframe(pd.DataFrame([{"type": k, "count": v} for k, v in r["inventory"].items()]),
                         hide_index=True, use_container_width=True)
            st.markdown("##### DPDP compliance report")
            st.json(r["dpdp"], expanded=False)


def page_siteguard():
    T.hero("SiteGuard", "Passive, non-intrusive security-posture scan of the firm's website "
           "and candidate portal.", eyebrow="Vulnerability Assessment")
    mode = st.radio("Mode", ["Offline demo", "Live scan (authorized)"], horizontal=True)
    res = None
    if mode == "Offline demo":
        target = st.selectbox("Demo target", list(ig.SITEGUARD_DEMOS))
        if st.button("▶️  Run demo scan", use_container_width=True):
            res = ig.siteguard_scan("", demo=target)
    else:
        url = st.text_input("Target URL", placeholder="https://www.jmdcareermaker.com")
        ok = st.checkbox("I confirm I own this domain or am authorized to test it.")
        if st.button("▶️  Run live scan", use_container_width=True):
            if not url or not ok:
                st.warning("Enter a URL and confirm authorization.")
            else:
                with st.spinner("Scanning…"):
                    res = ig.siteguard_scan(url, authorized=True)
    if res:
        a, b, c = st.columns([1, 1, 2])
        a.markdown(T.big_badge(res["grade"], "security grade"), unsafe_allow_html=True)
        b.metric("Posture score", f"{res['posture_score']}/100")
        c.metric("Findings", len(res["findings"]))
        if res["findings"]:
            st.markdown("##### Findings")
            st.dataframe(pd.DataFrame([{"severity": f["severity"], "title": f["title"],
                          "category": f["category"], "remediation": f["remediation"]}
                          for f in res["findings"]]), hide_index=True, use_container_width=True)
        else:
            st.success("No issues found — solid posture.")
        if res.get("info"):
            st.json({k: v for k, v in res["info"].items() if k != "target"}, expanded=False)


def page_breachradar():
    T.hero("BreachRadar", "Privacy-preserving credential-exposure monitoring for staff and "
           "recruiter accounts.", eyebrow="Threat Intelligence")
    t1, t2 = st.tabs(["Check an address", "Scan organisation"])
    with t1:
        email = st.text_input("Email", value="akash.mishra@jmdcareermaker.com")
        if st.button("🔎  Check exposure", use_container_width=True):
            x = ig.breachradar_check(email)
            a, b, c = st.columns([1.2, 1, 1])
            a.markdown(T.big_badge(x["risk_band"], f"{x['risk_score']}/100"), unsafe_allow_html=True)
            b.metric("Breaches", x["breach_count"])
            c.metric("Password exposed", "YES" if x["password_exposed"] else "no")
            if x["breaches"]:
                st.markdown("##### Where it appeared")
                st.dataframe(pd.DataFrame(x["breaches"]), hide_index=True, use_container_width=True)
            st.markdown("##### Recommended actions")
            for adv in x["advice"]:
                st.write("• " + adv)
    with t2:
        if st.button("📡  Scan organisation", use_container_width=True):
            org = ig.breachradar_scan_org()
            df = pd.DataFrame([{"email": x["email"], "risk": x["risk_band"],
                  "score": x["risk_score"], "breaches": x["breach_count"],
                  "password_exposed": x["password_exposed"]} for x in org])
            m = st.columns(3)
            m[0].metric("Monitored", len(df))
            m[1].metric("Exposed", int((df["breaches"] > 0).sum()))
            m[2].metric("HIGH/CRITICAL", int(df["risk"].isin(["CRITICAL", "HIGH"]).sum()))
            st.dataframe(df, hide_index=True, use_container_width=True)
            st.download_button("⬇️  Export report", df.to_csv(index=False),
                               "breachradar_report.csv")


PAGES = {
    "home": page_home, "phishguard": page_phishguard, "resumeshield": page_resumeshield,
    "siteguard": page_siteguard, "breachradar": page_breachradar,
}


def main():
    PAGES[sidebar()]()


if __name__ == "__main__":
    main()
