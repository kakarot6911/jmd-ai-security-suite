"""
Premium design system for the JMD Security Console.

Custom CSS + HTML/SVG components rendered via st.markdown(unsafe_allow_html=True).
Gauges use SVG SMIL animation (no JS) so rings animate on load and stay stable
across Streamlit versions. Interactive charts are built with Altair in app.py.
"""
from __future__ import annotations

import math

import streamlit as st

# Brand palette ------------------------------------------------------------
INK = "#0a0e17"
PANEL = "#121826"
PANEL_2 = "#192136"
LINE = "#26314d"
TEXT = "#eef2fb"
MUTED = "#93a1bd"
PRIMARY = "#6366f1"
PRIMARY_2 = "#8b5cf6"
ACCENT = "#22d3ee"

RISK = {
    "CRITICAL": "#f43f5e", "HIGH": "#fb923c", "MEDIUM": "#facc15",
    "LOW": "#34d399", "NONE": "#34d399", "INFO": "#7c8aa8",
    "A": "#34d399", "B": "#84cc16", "C": "#facc15", "D": "#fb923c", "F": "#f43f5e",
}

# Altair dark theme palette (used by charts in app.py)
CHART_BG = "transparent"
CHART_SEQ = [PRIMARY, ACCENT, PRIMARY_2, "#34d399", "#fb923c"]


def _css() -> str:
    return f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"] {{ font-family: 'Inter', -apple-system, sans-serif; }}
#MainMenu, header[data-testid="stHeader"], footer {{ visibility: hidden; }}

.stApp {{
  background:
    radial-gradient(1100px 560px at 8% -10%, rgba(99,102,241,.22), transparent 55%),
    radial-gradient(900px 560px at 112% -4%, rgba(34,211,238,.14), transparent 52%),
    radial-gradient(700px 700px at 50% 120%, rgba(139,92,246,.10), transparent 60%),
    {INK};
  color: {TEXT};
}}
.block-container {{ padding-top: 1.4rem; max-width: 1200px; animation: fadein .5s ease; }}
@keyframes fadein {{ from {{opacity:0; transform: translateY(8px);}} to {{opacity:1; transform:none;}} }}

::-webkit-scrollbar {{ width: 10px; height: 10px; }}
::-webkit-scrollbar-track {{ background: {INK}; }}
::-webkit-scrollbar-thumb {{ background: {LINE}; border-radius: 10px; }}
::-webkit-scrollbar-thumb:hover {{ background: {PRIMARY}; }}

/* Sidebar */
section[data-testid="stSidebar"] {{
  background: linear-gradient(180deg, {PANEL} 0%, {INK} 100%);
  border-right: 1px solid {LINE};
}}
section[data-testid="stSidebar"] * {{ color: {TEXT}; }}
section[data-testid="stSidebar"] [role="radiogroup"] label {{
  border-radius: 10px; padding: 6px 10px; transition: background .15s ease; margin: 1px 0;
}}
section[data-testid="stSidebar"] [role="radiogroup"] label:hover {{ background: {PANEL_2}; }}

/* Buttons */
.stButton > button, .stDownloadButton > button {{
  background: linear-gradient(135deg, {PRIMARY}, {PRIMARY_2});
  color: #fff; border: 0; border-radius: 12px; padding: .62rem 1.15rem;
  font-weight: 700; letter-spacing:.2px; position: relative; overflow: hidden;
  box-shadow: 0 10px 24px rgba(99,102,241,.38); transition: all .2s ease;
}}
.stButton > button:hover, .stDownloadButton > button:hover {{
  transform: translateY(-2px); box-shadow: 0 16px 34px rgba(99,102,241,.55); color:#fff;
  filter: brightness(1.06);
}}
.stButton > button:active {{ transform: translateY(0); }}

/* Inputs */
textarea, input, .stTextInput input, .stTextArea textarea, [data-baseweb="select"] > div {{
  background: {PANEL_2} !important; color: {TEXT} !important;
  border-radius: 11px !important; border: 1px solid {LINE} !important; transition: border .15s ease;
}}
textarea:focus, input:focus {{ border-color: {PRIMARY} !important;
  box-shadow: 0 0 0 3px rgba(99,102,241,.22) !important; }}

/* Progress bar */
.stProgress > div > div > div > div {{
  background: linear-gradient(90deg, {PRIMARY}, {ACCENT}) !important;
}}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {{ gap: 6px; border-bottom: 1px solid {LINE}; }}
.stTabs [data-baseweb="tab"] {{ background: transparent; padding: 8px 14px; color: {MUTED};
  border-radius: 10px 10px 0 0; transition: all .15s ease; }}
.stTabs [data-baseweb="tab"]:hover {{ color: {TEXT}; background: {PANEL}; }}
.stTabs [aria-selected="true"] {{ background: {PANEL_2}; color: {TEXT};
  box-shadow: inset 0 -2px 0 {PRIMARY}; }}

[data-testid="stDataFrame"] {{ border:1px solid {LINE}; border-radius: 12px; }}

/* ---- Custom components ---- */
.pg-hero {{ position: relative; overflow: hidden;
  background: linear-gradient(120deg, rgba(99,102,241,.26), rgba(139,92,246,.12) 55%, rgba(34,211,238,.14));
  background-size: 200% 200%; animation: heroShift 12s ease infinite;
  border: 1px solid {LINE}; border-radius: 24px; padding: 28px 32px; margin-bottom: 20px;
  box-shadow: 0 24px 60px rgba(0,0,0,.4); }}
@keyframes heroShift {{ 0%{{background-position:0% 50%}} 50%{{background-position:100% 50%}} 100%{{background-position:0% 50%}} }}
.pg-hero::after {{ content:''; position:absolute; top:-40%; right:-10%; width:320px; height:320px;
  background: radial-gradient(circle, rgba(34,211,238,.25), transparent 70%); filter: blur(10px); }}
.pg-hero h1 {{ font-size: 2.15rem; font-weight: 900; margin:0; letter-spacing:-.6px;
  background: linear-gradient(90deg, #fff, #c7d2fe); -webkit-background-clip: text;
  -webkit-text-fill-color: transparent; }}
.pg-hero p {{ color: #c3cce0; margin:.45rem 0 0; font-size:1.0rem; max-width: 760px; }}
.pg-eyebrow {{ display:inline-flex; align-items:center; gap:7px; font-size:.72rem; font-weight:800;
  letter-spacing:1.6px; text-transform:uppercase; color:{ACCENT}; margin-bottom:.55rem; }}
.pg-eyebrow::before {{ content:''; width:7px; height:7px; border-radius:50%; background:{ACCENT};
  box-shadow:0 0 10px {ACCENT}; animation: pulse 2s infinite; }}
@keyframes pulse {{ 0%,100%{{opacity:1}} 50%{{opacity:.35}} }}

.pg-tile {{ background: linear-gradient(160deg, {PANEL}, {PANEL_2}); border:1px solid {LINE};
  border-radius: 18px; padding: 18px 20px; box-shadow: 0 12px 30px rgba(0,0,0,.28);
  transition: transform .18s ease, border-color .18s ease; }}
.pg-tile:hover {{ transform: translateY(-3px); border-color: {PRIMARY}; }}
.pg-tile .lab {{ color:{MUTED}; font-weight:700; font-size:.72rem; text-transform:uppercase; letter-spacing:.7px; }}
.pg-tile .val {{ color:{TEXT}; font-weight:900; font-size:1.9rem; line-height:1.1; margin-top:4px; }}
.pg-tile .sub {{ color:{MUTED}; font-size:.78rem; margin-top:2px; }}

.pg-card {{ background: {PANEL}; border:1px solid {LINE}; border-radius: 20px; padding: 22px;
  box-shadow: 0 14px 36px rgba(0,0,0,.3); height: 100%; transition: transform .2s ease, border-color .2s ease;
  position: relative; overflow: hidden; }}
.pg-card:hover {{ transform: translateY(-4px); border-color: {PRIMARY}; }}
.pg-card::before {{ content:''; position:absolute; inset:0 auto auto 0; width:100%; height:3px;
  background: linear-gradient(90deg, {PRIMARY}, {ACCENT}); opacity:.0; transition: opacity .2s ease; }}
.pg-card:hover::before {{ opacity:1; }}
.pg-card h3 {{ margin:.4rem 0 .4rem; font-size:1.12rem; font-weight:800; color:{TEXT}; }}
.pg-card p {{ color:{MUTED}; font-size:.9rem; line-height:1.55; margin:0; }}
.pg-ico {{ font-size:1.9rem; filter: drop-shadow(0 4px 10px rgba(99,102,241,.5)); }}

.pg-badge {{ display:inline-flex; align-items:center; gap:7px; font-weight:800; font-size:.8rem;
  padding:6px 13px; border-radius:999px; }}
.pg-dot {{ width:8px; height:8px; border-radius:50%; display:inline-block; }}
.pg-chip {{ display:inline-flex; align-items:center; gap:6px; font-size:.74rem; font-weight:700;
  padding:4px 11px; border-radius:999px; margin:3px 6px 3px 0; }}

.pg-sec {{ display:flex; align-items:center; gap:10px; margin: 6px 0 12px; }}
.pg-sec .bar {{ width:4px; height:18px; border-radius:3px; background: linear-gradient(180deg,{PRIMARY},{ACCENT}); }}
.pg-sec h4 {{ margin:0; font-size:1.02rem; font-weight:800; color:{TEXT}; }}

.pg-foot {{ color:{MUTED}; font-size:.8rem; text-align:center; margin-top:28px;
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
            f"border:1px solid {color}55'><span class='pg-dot' style='background:{color};"
            f"box-shadow:0 0 8px {color}'></span>{label}</span>")


def chip(label: str, key: str) -> str:
    color = RISK.get(key.upper(), MUTED)
    return (f"<span class='pg-chip' style='background:{color}1f;color:{color};"
            f"border:1px solid {color}44'><span class='pg-dot' style='background:{color}'></span>{label}</span>")


def section(title: str):
    st.markdown(f"<div class='pg-sec'><span class='bar'></span><h4>{title}</h4></div>",
                unsafe_allow_html=True)


def stat_tile(label: str, value, sub: str = "", accent: str = PRIMARY) -> str:
    sub_html = f"<div class='sub'>{sub}</div>" if sub else ""
    return (f"<div class='pg-tile' style='border-top:3px solid {accent}'>"
            f"<div class='lab'>{label}</div><div class='val'>{value}</div>{sub_html}</div>")


def donut(value: float, band: str, center: str = "", label: str = "", size: int = 150) -> str:
    """Animated SVG donut gauge. `value` is 0-100."""
    value = max(0.0, min(100.0, float(value)))
    color = RISK.get(band.upper(), PRIMARY)
    r = 56
    circ = 2 * math.pi * r
    off = circ * (1 - value / 100.0)
    uid = f"g{abs(hash((value, band, center)))%99999}"
    ctxt = center if center else f"{int(round(value))}"
    return f"""
<div style="display:flex;flex-direction:column;align-items:center">
<svg width="{size}" height="{size}" viewBox="0 0 140 140">
  <defs><linearGradient id="{uid}" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0%" stop-color="{color}"/><stop offset="100%" stop-color="{color}99"/>
  </linearGradient></defs>
  <circle cx="70" cy="70" r="{r}" fill="none" stroke="{LINE}" stroke-width="13"/>
  <circle cx="70" cy="70" r="{r}" fill="none" stroke="url(#{uid})" stroke-width="13"
    stroke-linecap="round" transform="rotate(-90 70 70)"
    stroke-dasharray="{circ:.1f}" stroke-dashoffset="{circ:.1f}">
    <animate attributeName="stroke-dashoffset" from="{circ:.1f}" to="{off:.1f}"
      dur="1.1s" begin="0s" fill="freeze" calcMode="spline"
      keyTimes="0;1" keySplines="0.22 1 0.36 1"/>
  </circle>
  <text x="70" y="69" text-anchor="middle" dominant-baseline="middle"
    font-size="30" font-weight="800" fill="{TEXT}" font-family="Inter">{ctxt}</text>
  <text x="70" y="92" text-anchor="middle" font-size="11" fill="{MUTED}"
    font-family="Inter" letter-spacing="1">{band.upper()}</text>
</svg>
{f'<div style="color:{MUTED};font-size:.82rem;margin-top:2px">{label}</div>' if label else ''}
</div>"""


def big_badge(band: str, value: str = "") -> str:
    color = RISK.get(band.upper(), MUTED)
    sub = f"<div style='font-size:.85rem;opacity:.9'>{value}</div>" if value else ""
    return (f"<div style='background:linear-gradient(135deg,{color},{color}bb);color:#fff;"
            f"padding:18px 22px;border-radius:18px;box-shadow:0 16px 38px {color}55'>"
            f"<div style='font-size:.72rem;letter-spacing:1.2px;opacity:.9;text-transform:uppercase'>"
            f"Risk</div><div style='font-size:2.0rem;font-weight:900;line-height:1.1'>{band}</div>"
            f"{sub}</div>")


def tool_card(icon: str, title: str, desc: str, status: str = "Ready") -> str:
    return (f"<div class='pg-card'><div class='pg-ico'>{icon}</div>"
            f"<h3>{title}</h3><p>{desc}</p>"
            f"<div style='margin-top:14px'>{badge(status, 'LOW')}</div></div>")


def footer(text: str):
    st.markdown(f"<div class='pg-foot'>{text}</div>", unsafe_allow_html=True)
