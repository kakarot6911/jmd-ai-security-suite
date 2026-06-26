"""
Premium design system for the JMD Security Console.

A small, robust set of CSS rules + HTML component helpers. We render our own
HTML cards/badges (via st.markdown(unsafe_allow_html=True)) rather than overriding
Streamlit internals, so the look stays stable across Streamlit versions.
"""
from __future__ import annotations

import streamlit as st

# Brand palette ------------------------------------------------------------
INK = "#0b0e16"
PANEL = "#141a27"
PANEL_2 = "#1b2335"
LINE = "#2a3550"
TEXT = "#e7ebf3"
MUTED = "#94a3b8"
PRIMARY = "#6366f1"
PRIMARY_2 = "#8b5cf6"
ACCENT = "#22d3ee"

RISK = {
    "CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308",
    "LOW": "#22c55e", "NONE": "#22c55e", "INFO": "#64748b",
    "A": "#22c55e", "B": "#84cc16", "C": "#eab308", "D": "#f97316", "F": "#ef4444",
}


def _css() -> str:
    return f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

html, body, [class*="css"] {{ font-family: 'Inter', -apple-system, sans-serif; }}
#MainMenu, header[data-testid="stHeader"], footer {{ visibility: hidden; }}
.stApp {{
  background:
    radial-gradient(1200px 600px at 12% -8%, rgba(99,102,241,.18), transparent 55%),
    radial-gradient(1000px 600px at 110% 0%, rgba(34,211,238,.12), transparent 50%),
    {INK};
  color: {TEXT};
}}
.block-container {{ padding-top: 1.6rem; max-width: 1180px; }}

/* Sidebar */
section[data-testid="stSidebar"] {{
  background: linear-gradient(180deg, {PANEL} 0%, {INK} 100%);
  border-right: 1px solid {LINE};
}}
section[data-testid="stSidebar"] * {{ color: {TEXT}; }}

/* Buttons */
.stButton > button, .stDownloadButton > button {{
  background: linear-gradient(135deg, {PRIMARY}, {PRIMARY_2});
  color: #fff; border: 0; border-radius: 12px; padding: .6rem 1.1rem;
  font-weight: 600; letter-spacing:.2px;
  box-shadow: 0 8px 22px rgba(99,102,241,.35); transition: all .18s ease;
}}
.stButton > button:hover, .stDownloadButton > button:hover {{
  transform: translateY(-2px); box-shadow: 0 12px 28px rgba(99,102,241,.5); color:#fff;
}}

/* Inputs */
textarea, input, .stTextInput input, .stTextArea textarea, [data-baseweb="select"] > div {{
  background: {PANEL_2} !important; color: {TEXT} !important;
  border-radius: 10px !important; border: 1px solid {LINE} !important;
}}

/* Native metric -> card */
[data-testid="stMetric"] {{
  background: {PANEL}; border: 1px solid {LINE}; border-radius: 16px;
  padding: 16px 18px; box-shadow: 0 10px 30px rgba(0,0,0,.25);
}}
[data-testid="stMetricLabel"] p {{ color: {MUTED}; font-weight:600; font-size:.78rem;
  text-transform: uppercase; letter-spacing:.6px; }}
[data-testid="stMetricValue"] {{ color: {TEXT}; font-weight:800; }}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {{ gap: 6px; }}
.stTabs [data-baseweb="tab"] {{
  background: {PANEL}; border:1px solid {LINE}; border-radius: 10px 10px 0 0;
  padding: 8px 16px; color: {MUTED};
}}
.stTabs [aria-selected="true"] {{ background: {PANEL_2}; color: {TEXT}; }}

/* Dataframe container */
[data-testid="stDataFrame"] {{ border:1px solid {LINE}; border-radius: 12px; }}

/* Custom components */
.pg-hero {{
  background: linear-gradient(135deg, rgba(99,102,241,.22), rgba(139,92,246,.10) 60%, rgba(34,211,238,.10));
  border: 1px solid {LINE}; border-radius: 22px; padding: 26px 30px; margin-bottom: 18px;
  box-shadow: 0 20px 50px rgba(0,0,0,.35);
}}
.pg-hero h1 {{ font-size: 2.0rem; font-weight: 800; margin:0; letter-spacing:-.5px;
  background: linear-gradient(90deg, #fff, #c7d2fe); -webkit-background-clip: text;
  -webkit-text-fill-color: transparent; }}
.pg-hero p {{ color: {MUTED}; margin:.4rem 0 0; font-size:.98rem; }}
.pg-eyebrow {{ display:inline-block; font-size:.72rem; font-weight:700; letter-spacing:1.4px;
  text-transform:uppercase; color:{ACCENT}; margin-bottom:.5rem; }}

.pg-card {{ background: {PANEL}; border:1px solid {LINE}; border-radius: 18px;
  padding: 20px 22px; box-shadow: 0 12px 34px rgba(0,0,0,.28); height: 100%; }}
.pg-card h3 {{ margin:.2rem 0 .4rem; font-size:1.05rem; font-weight:700; color:{TEXT}; }}
.pg-card p {{ color:{MUTED}; font-size:.88rem; line-height:1.5; margin:0; }}
.pg-ico {{ font-size:1.6rem; }}

.pg-badge {{ display:inline-flex; align-items:center; gap:7px; font-weight:700;
  font-size:.8rem; padding:6px 13px; border-radius:999px; }}
.pg-dot {{ width:8px; height:8px; border-radius:50%; display:inline-block; }}

.pg-pill {{ display:inline-block; font-size:.72rem; font-weight:600; color:{MUTED};
  border:1px solid {LINE}; border-radius:999px; padding:3px 10px; margin-right:6px; }}
.pg-foot {{ color:{MUTED}; font-size:.8rem; text-align:center; margin-top:26px;
  border-top:1px solid {LINE}; padding-top:14px; }}
</style>
"""


def inject():
    st.markdown(_css(), unsafe_allow_html=True)


def hero(title: str, subtitle: str, eyebrow: str = "JMD The Career Maker · Security"):
    st.markdown(
        f"<div class='pg-hero'><div class='pg-eyebrow'>{eyebrow}</div>"
        f"<h1>{title}</h1><p>{subtitle}</p></div>", unsafe_allow_html=True)


def badge(label: str, key: str | None = None) -> str:
    color = RISK.get((key or label).upper(), MUTED)
    return (f"<span class='pg-badge' style='background:{color}22;color:{color};"
            f"border:1px solid {color}55'><span class='pg-dot' style='background:{color}'></span>"
            f"{label}</span>")


def big_badge(band: str, value: str = "") -> str:
    color = RISK.get(band.upper(), MUTED)
    sub = f"<div style='font-size:.85rem;opacity:.85'>{value}</div>" if value else ""
    return (f"<div style='background:linear-gradient(135deg,{color},{color}cc);color:#fff;"
            f"padding:18px 20px;border-radius:16px;box-shadow:0 14px 34px {color}40'>"
            f"<div style='font-size:.72rem;letter-spacing:1px;opacity:.9;text-transform:uppercase'>"
            f"Risk</div><div style='font-size:1.9rem;font-weight:800'>{band}</div>{sub}</div>")


def tool_card(icon: str, title: str, desc: str, status: str = "Ready") -> str:
    return (f"<div class='pg-card'><div class='pg-ico'>{icon}</div>"
            f"<h3>{title}</h3><p>{desc}</p>"
            f"<div style='margin-top:12px'>{badge(status, 'LOW')}</div></div>")


def footer(text: str):
    st.markdown(f"<div class='pg-foot'>{text}</div>", unsafe_allow_html=True)
