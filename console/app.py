"""
JMD Security Console — unified premium, interactive dashboard for all four tools.

Run:  streamlit run console/app.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import altair as alt
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
    "🔗  LinkGuard": "linkguard",
    "📡  BreachRadar": "breachradar",
}
BAND_DOMAIN = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "INFO"]
BAND_RANGE = [T.RISK[b] for b in BAND_DOMAIN]


# ---------------------------------------------------------------------------
# Chart helpers (interactive, dark-themed Altair)
# ---------------------------------------------------------------------------
def _style(chart):
    return (chart.configure_view(strokeWidth=0, fill="transparent")
            .configure_axis(labelColor=T.MUTED, titleColor=T.MUTED, gridColor="#1b2640",
                            domainColor=T.LINE, tickColor=T.LINE, labelFont="Inter",
                            titleFont="Inter", labelFontSize=11)
            .configure_legend(labelColor=T.MUTED, titleColor=T.MUTED)
            .properties(background="transparent"))


def band_bar(df: pd.DataFrame, label_col: str, value_col: str, band_col: str, height=None):
    h = height or max(120, 34 * len(df))
    chart = (alt.Chart(df).mark_bar(cornerRadiusEnd=6, height=20)
             .encode(
                 x=alt.X(f"{value_col}:Q", title=None),
                 y=alt.Y(f"{label_col}:N", sort="-x", title=None),
                 color=alt.Color(f"{band_col}:N",
                                 scale=alt.Scale(domain=BAND_DOMAIN, range=BAND_RANGE),
                                 legend=None),
                 tooltip=list(df.columns))
             .properties(height=h))
    st.altair_chart(_style(chart), use_container_width=True)


def count_bar(counts: dict, title: str = ""):
    df = pd.DataFrame([{"severity": k, "count": v} for k, v in counts.items() if v])
    if df.empty:
        return
    chart = (alt.Chart(df).mark_bar(cornerRadiusEnd=6)
             .encode(
                 x=alt.X("severity:N", sort=BAND_DOMAIN, title=None),
                 y=alt.Y("count:Q", title=None),
                 color=alt.Color("severity:N",
                                 scale=alt.Scale(domain=BAND_DOMAIN, range=BAND_RANGE), legend=None),
                 tooltip=["severity", "count"])
             .properties(height=200, title=title))
    st.altair_chart(_style(chart), use_container_width=True)


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
def sidebar() -> str:
    with st.sidebar:
        st.markdown(
            "<div style='padding:8px 2px 16px'>"
            "<div style='font-size:1.4rem;font-weight:900;letter-spacing:-.5px'>🛡️ JMD <span "
            "style='background:linear-gradient(90deg,#818cf8,#22d3ee);-webkit-background-clip:text;"
            "-webkit-text-fill-color:transparent'>Security</span></div>"
            "<div style='color:#93a1bd;font-size:.78rem;margin-top:2px'>Unified Security Console</div>"
            "</div>", unsafe_allow_html=True)
        choice = st.radio("Navigate", list(NAV.keys()), label_visibility="collapsed")
        st.markdown("<hr style='border-color:#26314d'>", unsafe_allow_html=True)
        online = sum(1 for t in ig.TOOLS if t["available"])
        st.markdown(
            f"<div style='font-size:.72rem;color:#93a1bd;text-transform:uppercase;letter-spacing:.6px;"
            f"font-weight:700'>Modules online · {online}/{len(ig.TOOLS)}</div>"
            "<div style='margin-top:10px'>" + "".join(
                f"<div style='display:flex;align-items:center;gap:8px;font-size:.84rem;margin:6px 0'>"
                f"<span style='width:7px;height:7px;border-radius:50%;background:"
                f"{'#34d399' if t['available'] else '#f43f5e'};box-shadow:0 0 8px "
                f"{'#34d399' if t['available'] else '#f43f5e'}'></span>{t['icon']} {t['name']}</div>"
                for t in ig.TOOLS) + "</div>", unsafe_allow_html=True)
        st.markdown("<hr style='border-color:#26314d'>", unsafe_allow_html=True)
        st.caption("Synthetic data · safe by default · 27 tests passing")
    return NAV[choice]


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
def page_home():
    T.hero("Security Operations Console",
           "One pane of glass for recruitment-fraud, candidate-data protection, web posture "
           "and credential-exposure monitoring across JMD The Career Maker.")

    org = ig.breachradar_scan_org()
    total = len(org)
    exposed = sum(1 for x in org if x["breach_count"] > 0)
    critical = sum(1 for x in org if x["risk_band"] in {"CRITICAL", "HIGH"})
    pwd = sum(1 for x in org if x["password_exposed"])

    tiles = st.columns(4)
    tiles[0].markdown(T.stat_tile("Modules online",
                                  f"{sum(t['available'] for t in ig.TOOLS)}/{len(ig.TOOLS)}",
                                  "all systems go", T.ACCENT), unsafe_allow_html=True)
    tiles[1].markdown(T.stat_tile("Accounts monitored", total, "staff + recruiter inboxes",
                                  T.PRIMARY), unsafe_allow_html=True)
    tiles[2].markdown(T.stat_tile("Exposed accounts", exposed, f"{pwd} with password leak",
                                  T.RISK["HIGH"]), unsafe_allow_html=True)
    tiles[3].markdown(T.stat_tile("High / critical", critical, "need action now",
                                  T.RISK["CRITICAL"]), unsafe_allow_html=True)

    st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
    left, right = st.columns([1, 1.5])
    with left:
        ratio = round(100 * critical / total) if total else 0
        band = "CRITICAL" if critical else "LOW"
        st.markdown("<div class='pg-tile' style='text-align:center'>"
                    "<div class='lab' style='margin-bottom:6px'>Org exposure index</div>"
                    + T.donut(ratio, band, center=f"{ratio}%", label="accounts at high/critical risk")
                    + "</div>", unsafe_allow_html=True)
    with right:
        T.section("Account risk distribution")
        df = pd.DataFrame([{"account": x["email"].split("@")[0], "score": x["risk_score"],
                            "risk": x["risk_band"], "breaches": x["breach_count"]} for x in org])
        band_bar(df, "account", "score", "risk")

    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
    T.section("Security modules")
    cols = st.columns(2)
    for i, t in enumerate(ig.TOOLS):
        with cols[i % 2]:
            st.markdown(T.tool_card(t["icon"], t["name"], t["desc"],
                                    "Online" if t["available"] else "Offline"),
                        unsafe_allow_html=True)
            st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
    T.footer("JMD Security Suite · PhishGuard · ResumeShield · SiteGuard · LinkGuard · BreachRadar — "
             "synthetic data · safe by default")


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
    text = st.text_area("Message / job offer", value=sv[0], height=170,
                        placeholder="Paste a recruitment email or job offer…")
    if st.button("🔍  Analyze message", use_container_width=True):
        if not text.strip():
            st.warning("Paste a message first."); return
        v = ig.phishguard_analyze(text, sender, company)
        a, b = st.columns([1, 1.6])
        with a:
            st.markdown(T.donut(v["fraud_probability"] * 100, v["risk_band"],
                                center=f"{v['fraud_probability']:.0%}", label="fraud probability"),
                        unsafe_allow_html=True)
        with b:
            st.markdown(T.big_badge(v["risk_band"], v["recommended_action"]), unsafe_allow_html=True)
            st.markdown(f"<div style='margin-top:10px'>"
                        f"{T.chip('Hard block: ' + ('YES' if v['hard_block'] else 'no'), 'CRITICAL' if v['hard_block'] else 'LOW')}"
                        f"{T.chip(str(len(v['flags'])) + ' red flags', 'HIGH' if v['flags'] else 'LOW')}"
                        f"</div>", unsafe_allow_html=True)
            st.info(v["rationale"])
        if v["flags"]:
            T.section("Security red flags")
            st.markdown("".join(
                T.chip(f["name"], "CRITICAL" if f["severity"] >= .8 else
                       "HIGH" if f["severity"] >= .5 else "MEDIUM") for f in v["flags"]),
                unsafe_allow_html=True)
            with st.expander("See full explanation of each flag", expanded=True):
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
    text = st.text_area("Resume text", value=sample, height=180)
    if st.button("🛡️  Scan & redact", use_container_width=True):
        if not text.strip():
            st.warning("Provide resume text."); return
        r = ig.resumeshield_redact(text, keep_last=keep_last)
        a, b = st.columns([1, 1.6])
        with a:
            st.markdown(T.donut(r["risk_score"], r["risk_band"], center=str(r["risk_score"]),
                                label="exposure score"), unsafe_allow_html=True)
        with b:
            safe = r["dpdp"]["compliant_to_share_as_is"]
            st.markdown(T.big_badge(r["risk_band"], f"{sum(r['inventory'].values())} PII items found"),
                        unsafe_allow_html=True)
            st.markdown(f"<div style='margin-top:10px'>"
                        f"{T.chip('Safe to share: ' + ('YES' if safe else 'NO'), 'LOW' if safe else 'CRITICAL')}"
                        f"{T.chip('DPDP: ' + r['dpdp']['regulation'].split(',')[0], 'INFO')}</div>",
                        unsafe_allow_html=True)
            if r["inventory"]:
                count_bar({k: v for k, v in r["inventory"].items()})
        left, right = st.columns([1.3, 1])
        with left:
            T.section("Redacted resume")
            st.code(r["redacted_text"], language="text")
            st.download_button("⬇️  Download redacted", r["redacted_text"], "resume_redacted.txt")
        with right:
            T.section("DPDP compliance report")
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
        a, b = st.columns([1, 1.6])
        with a:
            st.markdown(T.donut(res["posture_score"], res["grade"], center=res["grade"],
                                label="security grade"), unsafe_allow_html=True)
        with b:
            st.markdown(T.big_badge(res["grade"], f"posture {res['posture_score']}/100"),
                        unsafe_allow_html=True)
            counts: dict = {}
            for f in res["findings"]:
                counts[f["severity"]] = counts.get(f["severity"], 0) + 1
            st.markdown("<div style='margin-top:10px'>" + "".join(
                T.chip(f"{v} {k}", k) for k, v in counts.items()) + "</div>",
                unsafe_allow_html=True)
            count_bar(counts)
        if res["findings"]:
            T.section(f"Findings ({len(res['findings'])})")
            for f in res["findings"]:
                with st.expander(f"{f['severity']} · {f['title']}"):
                    st.markdown(f"**Category:** {f['category']}  \n"
                                f"**Evidence:** `{f['evidence']}`  \n"
                                f"**Remediation:** {f['remediation']}")
        else:
            st.success("No issues found — solid posture.")


def page_linkguard():
    T.hero("LinkGuard", "Lexical safety analysis of job links — catches typosquats, shorteners, "
           "homographs and credential traps that impersonate the firm.", eyebrow="URL Threat Analysis")
    samples = {"— type my own —": "", **ig.LINKGUARD_DEMOS}
    choice = st.selectbox("Try a sample link", list(samples))
    url = st.text_input("URL", value=samples[choice],
                        placeholder="https://jmdcareermaker.com/careers")
    if st.button("▶️  Analyze link", use_container_width=True) and url:
        v = ig.linkguard_analyze(url)
        a, b = st.columns([1, 1.6])
        with a:
            st.markdown(T.donut(v["risk_score"], v["risk_band"], center=str(v["risk_score"]),
                                label="risk score"), unsafe_allow_html=True)
        with b:
            st.markdown(T.big_badge(v["risk_band"], v["verdict"]), unsafe_allow_html=True)
            dest_band = ("LOW" if v["matches_official"] else
                         "CRITICAL" if v["brand_impersonation"] else "INFO")
            dest_label = ("Official domain" if v["matches_official"] else
                          "Impersonation" if v["brand_impersonation"] else "Unknown party")
            ml = v.get("ml_probability")
            ml_chip = ("" if ml is None else
                       T.chip(f"ML: {ml:.0%} malicious", "CRITICAL" if ml >= 0.8 else
                              "HIGH" if ml >= 0.5 else "LOW"))
            st.markdown("<div style='margin-top:10px'>"
                        f"{T.chip('Real destination: ' + (v['registrable_domain'] or '—'), dest_band)}"
                        f"{T.chip(dest_label, dest_band)}"
                        f"{T.chip('HTTPS' if v['is_https'] else 'No HTTPS', 'LOW' if v['is_https'] else 'MEDIUM')}"
                        f"{ml_chip}"
                        "</div>", unsafe_allow_html=True)
        flagged = [s for s in v["signals"] if s["weight"]]
        if flagged:
            T.section(f"Signals ({len(flagged)})")
            st.dataframe(pd.DataFrame([
                {"severity": s["severity"], "signal": s["name"],
                 "weight": s["weight"], "why": s["detail"]} for s in flagged]),
                hide_index=True, use_container_width=True)
        else:
            st.success("No red-flag signals — link looks clean.")
        T.section("Recommended action")
        for adv in v["advice"]:
            st.markdown(f"- {adv}")


def page_breachradar():
    T.hero("BreachRadar", "Privacy-preserving credential-exposure monitoring for staff and "
           "recruiter accounts.", eyebrow="Threat Intelligence")
    t1, t2 = st.tabs(["🔎 Check an address", "📡 Scan organisation"])
    with t1:
        email = st.text_input("Email", value="akash.mishra@jmdcareermaker.com")
        if st.button("Check exposure", use_container_width=True):
            x = ig.breachradar_check(email)
            a, b = st.columns([1, 1.6])
            with a:
                st.markdown(T.donut(x["risk_score"], x["risk_band"], center=str(x["risk_score"]),
                                    label="exposure score"), unsafe_allow_html=True)
            with b:
                st.markdown(T.big_badge(x["risk_band"], f"{x['breach_count']} known breach(es)"),
                            unsafe_allow_html=True)
                st.markdown("<div style='margin-top:10px'>"
                            f"{T.chip('Password exposed: ' + ('YES' if x['password_exposed'] else 'no'), 'CRITICAL' if x['password_exposed'] else 'LOW')}"
                            f"{T.chip('High-value target' if x['high_value_target'] else 'Standard account', 'HIGH' if x['high_value_target'] else 'INFO')}"
                            "</div>", unsafe_allow_html=True)
            if x["breaches"]:
                T.section("Where it appeared")
                st.dataframe(pd.DataFrame(x["breaches"]), hide_index=True, use_container_width=True)
            T.section("Recommended actions")
            for adv in x["advice"]:
                st.markdown(f"- {adv}")
    with t2:
        if st.button("Scan organisation", use_container_width=True):
            org = ig.breachradar_scan_org()
            df = pd.DataFrame([{"account": x["email"].split("@")[0], "email": x["email"],
                  "risk": x["risk_band"], "score": x["risk_score"], "breaches": x["breach_count"],
                  "password_exposed": x["password_exposed"]} for x in org])
            m = st.columns(3)
            m[0].markdown(T.stat_tile("Monitored", len(df), accent=T.PRIMARY), unsafe_allow_html=True)
            m[1].markdown(T.stat_tile("Exposed", int((df["breaches"] > 0).sum()), accent=T.RISK["HIGH"]),
                          unsafe_allow_html=True)
            m[2].markdown(T.stat_tile("High / critical",
                          int(df["risk"].isin(["CRITICAL", "HIGH"]).sum()), accent=T.RISK["CRITICAL"]),
                          unsafe_allow_html=True)
            st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
            T.section("Exposure by account")
            band_bar(df[["account", "score", "risk", "breaches"]], "account", "score", "risk")
            st.dataframe(df.drop(columns=["account"]), hide_index=True, use_container_width=True)
            st.download_button("⬇️  Export report", df.to_csv(index=False),
                               "breachradar_report.csv")


PAGES = {
    "home": page_home, "phishguard": page_phishguard, "resumeshield": page_resumeshield,
    "siteguard": page_siteguard, "linkguard": page_linkguard, "breachradar": page_breachradar,
}


def main():
    PAGES[sidebar()]()


if __name__ == "__main__":
    main()
