/* JMD Security Console — interactive frontend (vanilla JS, talks to the FastAPI backend) */
"use strict";

const RISK = { CRITICAL:"#f43f5e", HIGH:"#fb923c", MEDIUM:"#facc15", LOW:"#34d399",
  NONE:"#34d399", INFO:"#7c8aa8", A:"#34d399", B:"#84cc16", C:"#facc15", D:"#fb923c", F:"#f43f5e" };
const rc = b => RISK[(b||"").toUpperCase()] || "#7c8aa8";
const $ = sel => document.querySelector(sel);
const esc = s => String(s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

// Optional API key: read from a <meta name="jmd-api-key"> tag so an auth-enabled
// deployment can serve the site with a working demo key injected at deploy time.
// The public demo ships with no key (auth off), so this is simply absent.
const API_KEY = (document.querySelector('meta[name="jmd-api-key"]') || {}).content || "";

async function api(path, body, method) {
  const headers = {"Content-Type":"application/json"};
  if (API_KEY) headers["X-API-Key"] = API_KEY;
  const opt = { method: method || (body ? "POST" : "GET"), headers };
  if (body) opt.body = JSON.stringify(body);
  const r = await fetch(path, opt);
  if (!r.ok) {
    let detail = r.statusText;
    try { detail = (await r.json()).detail || detail; } catch (e) {}
    throw new Error(detail);
  }
  return r.json();
}

function toast(msg) {
  const t = document.createElement("div");
  t.className = "toast"; t.textContent = "⚠️ " + msg;
  $("#toast").appendChild(t);
  setTimeout(() => t.remove(), 5000);
}

async function withLoading(btn, label, fn) {
  const orig = btn.innerHTML; btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span> ${label}`;
  try { await fn(); }
  catch (e) { toast(e.message || String(e)); }
  finally { btn.disabled = false; btn.innerHTML = orig; }
}

/* ---- components ---- */
function donut(value, band, center, label) {
  value = Math.max(0, Math.min(100, +value || 0));
  const color = rc(band), r = 56, circ = 2 * Math.PI * r, off = circ * (1 - value / 100);
  const uid = "g" + Math.random().toString(36).slice(2, 8);
  return `<div class="center">
    <svg width="150" height="150" viewBox="0 0 140 140">
      <defs><linearGradient id="${uid}" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stop-color="${color}"/><stop offset="100%" stop-color="${color}99"/></linearGradient></defs>
      <circle cx="70" cy="70" r="${r}" fill="none" stroke="#26314d" stroke-width="13"/>
      <circle class="ring" cx="70" cy="70" r="${r}" fill="none" stroke="url(#${uid})" stroke-width="13"
        stroke-linecap="round" transform="rotate(-90 70 70)"
        stroke-dasharray="${circ.toFixed(1)}" stroke-dashoffset="${circ.toFixed(1)}"
        data-off="${off.toFixed(1)}" style="transition:stroke-dashoffset 1.1s cubic-bezier(.22,1,.36,1)"/>
      <text x="70" y="69" text-anchor="middle" dominant-baseline="middle" font-size="30"
        font-weight="800" fill="#eef2fb" font-family="Inter">${esc(center)}</text>
      <text x="70" y="92" text-anchor="middle" font-size="11" fill="#93a1bd"
        font-family="Inter" letter-spacing="1">${esc((band||"").toUpperCase())}</text>
    </svg>${label ? `<div class="muted" style="font-size:.82rem">${esc(label)}</div>` : ""}</div>`;
}
function animateDonuts(scope) {
  (scope || document).querySelectorAll(".ring").forEach(c => {
    requestAnimationFrame(() => { c.style.strokeDashoffset = c.dataset.off; });
  });
}
function bigBadge(band, sub) {
  const c = rc(band);
  return `<div class="bigbadge" style="background:linear-gradient(135deg,${c},${c}bb);box-shadow:0 16px 38px ${c}55">
    <div class="t">Risk</div><div class="b">${esc(band)}</div>${sub ? `<div class="s">${esc(sub)}</div>` : ""}</div>`;
}
function chip(label, key) {
  const c = rc(key);
  return `<span class="chip" style="background:${c}1f;color:${c};border:1px solid ${c}44">
    <span class="dot" style="background:${c}"></span>${esc(label)}</span>`;
}
function bars(items) {
  const max = Math.max(1, ...items.map(i => i.value));
  return `<div class="bars">` + items.map(i => {
    const c = rc(i.band); const w = Math.round(100 * i.value / max);
    return `<div class="b"><span class="muted">${esc(i.label)}</span>
      <div class="track"><div class="fill" data-w="${w}" style="background:linear-gradient(90deg,${c},${c}aa)"></div></div>
      <span style="text-align:right">${esc(i.value)}</span></div>`;
  }).join("") + `</div>`;
}
function animateBars(scope) {
  (scope || document).querySelectorAll(".fill").forEach(f =>
    requestAnimationFrame(() => { f.style.width = f.dataset.w + "%"; }));
}
function tile(lab, val, sub, accent) {
  return `<div class="tile" style="border-top:3px solid ${accent}">
    <div class="lab">${esc(lab)}</div><div class="val">${esc(val)}</div>
    ${sub ? `<div class="sub">${esc(sub)}</div>` : ""}</div>`;
}

/* ---- navigation ---- */
$("#nav").addEventListener("click", e => {
  const b = e.target.closest("button"); if (!b) return;
  document.querySelectorAll(".nav button").forEach(x => x.classList.remove("active"));
  b.classList.add("active");
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  const view = $("#view-" + b.dataset.view); view.classList.add("active");
  animateDonuts(view); animateBars(view);
});

/* ---- overview ---- */
const TOOLS = [
  ["🛡️","PhishGuard","Detects fake job offers, recruitment scams & phishing impersonating the firm.","phishguard"],
  ["🪪","ResumeShield","Redacts candidate PII and reports DPDP Act 2023 compliance before sharing resumes.","resumeshield"],
  ["🔐","SiteGuard","Passive web security-posture scanner for the firm's site & candidate portal.","siteguard"],
  ["🔗","LinkGuard","Flags typosquats, shorteners & impersonation in job links sent to or from candidates.","linkguard"],
  ["📡","BreachRadar","Monitors staff/recruiter accounts for exposure in known data breaches.","breachradar"],
];
async function loadHome() {
  try {
    const health = await api("/health");
    const mods = health.modules || {};
    const n = TOOLS.length;
    $("#statusLab").textContent = "Modules · " + Object.values(mods).filter(Boolean).length + "/" + n;
    $("#statusList").innerHTML = TOOLS.map(t => {
      const on = mods[t[3]] !== false;
      return `<div class="row" style="display:flex"><span class="dot ${on?"on":"off"}"></span>${t[0]} ${t[1]}</div>`;
    }).join("");

    $("#toolCards").innerHTML = TOOLS.map(t =>
      `<div class="card"><div class="ico">${t[0]}</div><h3>${t[1]}</h3><p>${t[2]}</p>
       <div style="margin-top:14px">${chip("Online","LOW")}</div></div>`).join("");

    const org = await api("/breachradar/scan-org");
    const total = org.length, exposed = org.filter(x => x.breach_count > 0).length;
    const crit = org.filter(x => ["CRITICAL","HIGH"].includes(x.risk_band)).length;
    const pwd = org.filter(x => x.password_exposed).length;
    $("#kpis").innerHTML =
      tile("Modules online", n + "/" + n, "all systems go","#22d3ee") +
      tile("Accounts monitored", total, "staff + recruiter inboxes","#6366f1") +
      tile("Exposed accounts", exposed, pwd + " with password leak", RISK.HIGH) +
      tile("High / critical", crit, "need action now", RISK.CRITICAL);

    const ratio = total ? Math.round(100 * crit / total) : 0;
    $("#orgDonut").innerHTML = `<div class="lab" style="margin-bottom:6px;color:#93a1bd">Org exposure index</div>` +
      donut(ratio, crit ? "CRITICAL" : "LOW", ratio + "%", "accounts at high/critical risk");
    $("#orgBars").innerHTML = bars(org.map(x => ({ label: x.email.split("@")[0], value: x.risk_score, band: x.risk_band })));
    animateDonuts($("#view-home")); animateBars($("#view-home"));
  } catch (e) { toast("Backend unreachable: " + e.message); }
}

/* ---- phishguard ---- */
const PH_SAMPLES = {
  "Scam · upfront fee": ["Congratulations! You are SELECTED for the AI Cybersecurity Intern role at JMD The Career Maker without any interview. Pay a refundable registration fee of Rs. 1,999 today. Limited slots, act now! http://bit.ly/jmd-offer","jmd.careers.official@gmail.com","JMD The Career Maker"],
  "Legit · interview invite": ["Dear Fazal Ahmad, thank you for applying to the AI Cybersecurity Intern position at JMD The Career Maker. We would like to invite you to a virtual interview. No fee is required at any stage.","akash.mishra@jmdcareermaker.com","JMD The Career Maker"],
};
$("#phishSamples").innerHTML = Object.keys(PH_SAMPLES).map(k =>
  `<button class="btn ghost" data-s="${esc(k)}">${esc(k)}</button>`).join("");
$("#phishSamples").addEventListener("click", e => {
  const b = e.target.closest("button"); if (!b) return;
  const s = PH_SAMPLES[b.dataset.s]; $("#phText").value = s[0]; $("#phSender").value = s[1]; $("#phCompany").value = s[2];
});
$("#phBtn").addEventListener("click", () => withLoading($("#phBtn"), "Analyzing…", async () => {
  const text = $("#phText").value.trim();
  if (!text) { toast("Paste a message first."); return; }
  const v = await api("/phishguard/analyze", { text, sender_email: $("#phSender").value, claimed_company: $("#phCompany").value });
  const flags = (v.flags || []).map(f => chip(f.name, f.severity >= .8 ? "CRITICAL" : f.severity >= .5 ? "HIGH" : "MEDIUM")).join("");
  const rows = (v.flags || []).map(f => `<tr><td>${chip(f.severity.toFixed(2), f.severity>=.8?"CRITICAL":f.severity>=.5?"HIGH":"MEDIUM")}</td><td>${esc(f.name)}</td><td>${esc(f.description)}</td></tr>`).join("");
  $("#phResult").innerHTML = `<div class="split">
      ${donut(v.fraud_probability*100, v.risk_band, Math.round(v.fraud_probability*100)+"%", "fraud probability")}
      <div>${bigBadge(v.risk_band, v.recommended_action)}
        <div style="margin-top:10px">${chip("Hard block: "+(v.hard_block?"YES":"no"), v.hard_block?"CRITICAL":"LOW")}${chip((v.flags||[]).length+" red flags", (v.flags||[]).length?"HIGH":"LOW")}</div>
        <div class="notice">${esc(v.rationale)}</div></div></div>
    ${flags ? `<div class="sec"><span class="bar"></span><h4>Security red flags</h4></div>${flags}
      <table><thead><tr><th>Severity</th><th>Rule</th><th>Why it matters</th></tr></thead><tbody>${rows}</tbody></table>`
      : `<div class="notice ok">No deterministic red flags fired.</div>`}`;
  animateDonuts($("#phResult"));
}));

/* ---- resumeshield ---- */
$("#rsText").value = "Name: Fazal Ahmad\nEmail: fazal.ahmad@example.com   Phone: +91 98765 43210\nAadhaar: 2994 1855 6015    PAN: ABCDE1234F\nA/c 123456789012 (HDFC Bank)\nDOB: 23/08/2001   Address: Tower 28, Lodha Belmondo, Pune 411045";
$("#rsKeep").addEventListener("input", e => $("#rsKeepVal").textContent = e.target.value);
$("#rsBtn").addEventListener("click", () => withLoading($("#rsBtn"), "Scanning…", async () => {
  const text = $("#rsText").value.trim();
  if (!text) { toast("Provide resume text."); return; }
  const r = await api("/resumeshield/redact", { text, keep_last: +$("#rsKeep").value });
  const inv = Object.entries(r.inventory || {});
  const safe = r.dpdp.compliant_to_share_as_is;
  $("#rsResult").innerHTML = `<div class="split">
      ${donut(r.risk_score, r.risk_band, r.risk_score, "exposure score")}
      <div>${bigBadge(r.risk_band, inv.reduce((a,[,v])=>a+v,0)+" PII items found")}
        <div style="margin-top:10px">${chip("Safe to share: "+(safe?"YES":"NO"), safe?"LOW":"CRITICAL")}${chip("DPDP Act 2023","INFO")}</div></div></div>
    <div class="grid g2" style="margin-top:14px">
      <div><div class="sec"><span class="bar"></span><h4>Redacted resume</h4></div>
        <pre class="redacted">${esc(r.redacted_text)}</pre></div>
      <div><div class="sec"><span class="bar"></span><h4>PII inventory</h4></div>
        ${bars(inv.map(([k,v]) => ({label:k, value:v, band:"HIGH"})))}</div></div>`;
  animateDonuts($("#rsResult")); animateBars($("#rsResult"));
}));

/* ---- siteguard ---- */
$("#sgMode").addEventListener("change", e => {
  const live = e.target.value === "live";
  $("#sgDemoWrap").style.display = live ? "none" : "";
  $("#sgUrlWrap").style.display = live ? "" : "none";
  $("#sgAuthWrap").style.display = live ? "" : "none";
});
$("#sgBtn").addEventListener("click", () => withLoading($("#sgBtn"), "Scanning…", async () => {
  let body;
  if ($("#sgMode").value === "demo") body = { demo: $("#sgDemo").value };
  else {
    if (!$("#sgUrl").value || !$("#sgAuth").checked) { toast("Enter a URL and confirm authorization."); return; }
    body = { url: $("#sgUrl").value, authorized: true };
  }
  const res = await api("/siteguard/scan", body);
  const counts = {}; (res.findings||[]).forEach(f => counts[f.severity] = (counts[f.severity]||0)+1);
  const chips = Object.entries(counts).map(([k,v]) => chip(v+" "+k, k)).join("");
  const acc = (res.findings||[]).map(f => `<details class="acc"><summary>${chip(f.severity,f.severity)} ${esc(f.title)}</summary>
      <div class="body"><b>Category:</b> ${esc(f.category)}<br><b>Evidence:</b> <code>${esc(f.evidence)}</code><br><b>Remediation:</b> ${esc(f.remediation)}</div></details>`).join("");
  $("#sgResult").innerHTML = `<div class="split">
      ${donut(res.posture_score, res.grade, res.grade, "security grade")}
      <div>${bigBadge(res.grade, "posture "+res.posture_score+"/100")}
        <div style="margin-top:10px">${chips||chip("clean","LOW")}</div></div></div>
    ${ (res.findings||[]).length ? `<div class="sec"><span class="bar"></span><h4>Findings (${res.findings.length})</h4></div>${acc}`
       : `<div class="notice ok">No issues found — solid posture.</div>`}`;
  animateDonuts($("#sgResult"));
}));

/* ---- linkguard ---- */
const LG_SAMPLES = {
  "Official page": "https://jmdcareermaker.com/careers/ai-cybersecurity-intern",
  "Shortened link": "http://bit.ly/jmd-offer",
  "Typosquat": "https://jmdcaremaker.com/login",
  "Brand in subdomain": "https://jmdcareermaker.com.secure-login.ru/verify",
  "@-trap": "http://jmdcareermaker.com@192.168.0.5/pay?token=abc123",
  "Punycode": "https://xn--jmdcareermker-9zb.com/account",
};
$("#lgSamples").innerHTML = Object.keys(LG_SAMPLES).map(k =>
  `<button class="btn ghost" data-s="${esc(k)}">${esc(k)}</button>`).join("");
$("#lgSamples").addEventListener("click", e => {
  const b = e.target.closest("button"); if (!b) return;
  $("#lgUrl").value = LG_SAMPLES[b.dataset.s];
});
$("#lgBtn").addEventListener("click", () => withLoading($("#lgBtn"), "Analyzing…", async () => {
  const url = $("#lgUrl").value.trim();
  if (!url) { toast("Paste a link first."); return; }
  const v = await api("/linkguard/analyze", { url });
  const destBand = v.matches_official ? "LOW" : v.brand_impersonation ? "CRITICAL" : "INFO";
  const destLabel = v.matches_official ? "Official domain" : v.brand_impersonation ? "Impersonation" : "Unknown party";
  const mlChip = (v.ml_probability == null) ? "" :
    chip("ML: " + Math.round(v.ml_probability*100) + "% malicious",
         v.ml_probability >= 0.8 ? "CRITICAL" : v.ml_probability >= 0.5 ? "HIGH" : "LOW");
  const sigs = (v.signals || []).filter(s => s.weight);
  const rows = sigs.map(s => `<tr><td>${chip(s.severity, s.severity)}</td><td>${esc(s.name)}</td><td>${s.weight}</td><td>${esc(s.detail)}</td></tr>`).join("");
  $("#lgResult").innerHTML = `<div class="split">
      ${donut(v.risk_score, v.risk_band, v.risk_score, "risk score")}
      <div>${bigBadge(v.risk_band, v.verdict)}
        <div style="margin-top:10px">${chip("Real destination: "+(v.registrable_domain||"—"), destBand)}${chip(destLabel, destBand)}${chip(v.is_https?"HTTPS":"No HTTPS", v.is_https?"LOW":"MEDIUM")}${mlChip}</div></div></div>
    ${sigs.length ? `<div class="sec"><span class="bar"></span><h4>Signals (${sigs.length})</h4></div>
      <table><thead><tr><th>Severity</th><th>Signal</th><th>Weight</th><th>Why it matters</th></tr></thead><tbody>${rows}</tbody></table>`
      : `<div class="notice ok">No red-flag signals — link looks clean.</div>`}
    <div class="sec"><span class="bar"></span><h4>Recommended action</h4></div>
    <ul class="muted">${(v.advice||[]).map(a=>`<li>${esc(a)}</li>`).join("")}</ul>`;
  animateDonuts($("#lgResult"));
}));

/* ---- breachradar ---- */
$("#brBtn").addEventListener("click", () => withLoading($("#brBtn"), "Checking…", async () => {
  const x = await api("/breachradar/check", { email: $("#brEmail").value });
  const brows = (x.breaches||[]).map(b => `<tr><td>${esc(b.breach)}</td><td>${esc(b.date)}</td><td>${chip(b.severity,b.severity)}</td><td>${(b.classes||[]).join(", ")}</td><td>${b.password_exposed?"YES":"no"}</td></tr>`).join("");
  $("#brResult").innerHTML = `<div class="split">
      ${donut(x.risk_score, x.risk_band, x.risk_score, "exposure score")}
      <div>${bigBadge(x.risk_band, x.breach_count+" known breach(es)")}
        <div style="margin-top:10px">${chip("Password exposed: "+(x.password_exposed?"YES":"no"), x.password_exposed?"CRITICAL":"LOW")}${chip(x.high_value_target?"High-value target":"Standard account", x.high_value_target?"HIGH":"INFO")}</div></div></div>
    ${ (x.breaches||[]).length ? `<div class="sec"><span class="bar"></span><h4>Where it appeared</h4></div>
       <table><thead><tr><th>Breach</th><th>Date</th><th>Severity</th><th>Data</th><th>Password</th></tr></thead><tbody>${brows}</tbody></table>` : "" }
    <div class="sec"><span class="bar"></span><h4>Recommended actions</h4></div>
    <ul class="muted">${(x.advice||[]).map(a=>`<li>${esc(a)}</li>`).join("")}</ul>`;
  animateDonuts($("#brResult"));
}));
$("#brOrgBtn").addEventListener("click", () => withLoading($("#brOrgBtn"), "Scanning…", async () => {
  const org = await api("/breachradar/scan-org");
  const exposed = org.filter(x=>x.breach_count>0).length;
  const crit = org.filter(x=>["CRITICAL","HIGH"].includes(x.risk_band)).length;
  const rows = org.map(x=>`<tr><td>${esc(x.email)}</td><td>${chip(x.risk_band,x.risk_band)}</td><td>${x.risk_score}</td><td>${x.breach_count}</td><td>${x.password_exposed?"YES":"no"}</td></tr>`).join("");
  $("#brResult").innerHTML = `<div class="grid g3">
      ${tile("Monitored", org.length, "", "#6366f1")}${tile("Exposed", exposed, "", RISK.HIGH)}${tile("High / critical", crit, "", RISK.CRITICAL)}</div>
    <div class="sec"><span class="bar"></span><h4>Exposure by account</h4></div>
    ${bars(org.map(x=>({label:x.email.split("@")[0], value:x.risk_score, band:x.risk_band})))}
    <table style="margin-top:12px"><thead><tr><th>Account</th><th>Risk</th><th>Score</th><th>Breaches</th><th>Password</th></tr></thead><tbody>${rows}</tbody></table>`;
  animateBars($("#brResult"));
}));

/* boot */
loadHome();
