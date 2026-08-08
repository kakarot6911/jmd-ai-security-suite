import { Fingerprint, IdCard, Link2, Radar, ShieldAlert } from "lucide-react";
import { Card, Eyebrow, Lede, Reveal, Section, SectionHeading } from "./primitives.jsx";

/* --- inline visuals ------------------------------------------------------ */

function Sparkline() {
  // 71.3% -> 100%: the measured accuracy lift, drawn from the real eval numbers.
  const pts = [71.3, 76.9, 84, 88, 93.5, 97, 100];
  const d = pts
    .map((v, i) => {
      const x = (i / (pts.length - 1)) * 100;
      const y = 34 - ((v - 68) / 34) * 30;
      return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  return (
    <svg viewBox="0 0 100 38" className="h-14 w-full" role="img" aria-label="Accuracy rising from 71.3% to 100%">
      <defs>
        <linearGradient id="spark" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#00ff94" stopOpacity="0.32" />
          <stop offset="100%" stopColor="#00ff94" stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={`${d} L100,38 L0,38 Z`} fill="url(#spark)" />
      <path d={d} fill="none" stroke="#00ff94" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="100" cy={34 - ((100 - 68) / 34) * 30} r="2" fill="#00ff94" />
    </svg>
  );
}

function ThreatBars() {
  const rows = [
    { label: "typosquat", pct: 96, tone: "bg-danger" },
    { label: "shortener", pct: 74, tone: "bg-[#ff8f3c]" },
    { label: "homoglyph", pct: 88, tone: "bg-danger" },
    { label: "official", pct: 6, tone: "bg-live" },
  ];
  return (
    <div className="space-y-2">
      {rows.map((r) => (
        <div key={r.label} className="flex items-center gap-3">
          <span className="w-20 shrink-0 font-mono text-[10px] text-ink-3">{r.label}</span>
          <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/[0.06]">
            <span className={`block h-full rounded-full ${r.tone}`} style={{ width: `${r.pct}%` }} />
          </span>
          <span className="w-8 shrink-0 text-right font-mono text-[10px] text-ink-2">{r.pct}</span>
        </div>
      ))}
    </div>
  );
}

function RedactedSnippet() {
  return (
    <pre className="overflow-x-auto rounded-lg border border-white/[0.06] bg-black/60 p-3 font-mono text-[10.5px] leading-relaxed text-ink-2">
      <code>
        {"Aadhaar: "}<span className="text-danger">XXXX XXXX 6015</span>{"\n"}
        {"PAN:     "}<span className="text-danger">XXXXX1234X</span>{"\n"}
        {"IFSC:    "}<span className="text-danger">XXXX0001234</span>{"\n"}
        {"UPI:     "}<span className="text-danger">XXXXX@okhdfcbank</span>
      </code>
    </pre>
  );
}

function PwnedCounter() {
  return (
    <div className="rounded-lg border border-white/[0.06] bg-black/60 p-3.5">
      <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-3">password123</div>
      <div className="mt-1 font-mono text-xl font-semibold text-danger">2,266,543</div>
      <div className="font-mono text-[10px] text-ink-3">real sightings · k-anonymous lookup</div>
    </div>
  );
}

function GradePill() {
  return (
    <div className="flex items-center gap-3">
      <div className="grid size-11 shrink-0 place-items-center rounded-lg border border-danger/40 bg-danger/10 font-mono text-lg font-semibold text-danger">
        F
      </div>
      <div className="font-mono text-[10.5px] leading-relaxed text-ink-3">
        <div><span className="text-ink-2">csp-weak</span> · permissive policy</div>
        <div><span className="text-ink-2">hsts-weak</span> · max-age=0</div>
      </div>
    </div>
  );
}

const TOOLS = [
  {
    icon: ShieldAlert, name: "PhishGuard", span: "lg:col-span-2",
    desc: "Catches fake offers, upfront-fee demands and credential harvesting — and refuses to call anything fraud without a red flag to show for it.",
    visual: <Sparkline />,
    tag: "76.9% → 100% accuracy",
  },
  {
    icon: Link2, name: "LinkGuard", span: "lg:col-span-1",
    desc: "Lexical URL analysis with a trained classifier.",
    visual: <ThreatBars />,
    tag: "16 signal types",
  },
  {
    icon: IdCard, name: "ResumeShield", span: "lg:col-span-1",
    desc: "DPDP-compliant PII redaction for candidate documents.",
    visual: <RedactedSnippet />,
    tag: "Aadhaar · PAN · IFSC · UAN",
  },
  {
    icon: Radar, name: "BreachRadar", span: "lg:col-span-1",
    desc: "Live credential exposure via k-anonymity.",
    visual: <PwnedCounter />,
    tag: "real HIBP data",
  },
  {
    icon: Fingerprint, name: "SiteGuard", span: "lg:col-span-1",
    desc: "Grades header values, not just their presence.",
    visual: <GradePill />,
    tag: "SSRF-guarded",
  },
];

export default function Bento() {
  return (
    <Section id="capabilities" className="py-24 md:py-32">
      <Reveal>
        <Eyebrow>Capabilities</Eyebrow>
        <SectionHeading>Five tools. One threat surface.</SectionHeading>
        <Lede>
          A career consultancy handles resumes full of government IDs, sends job links every day,
          and is impersonated constantly. Each tool closes one of those doors — and explains every
          verdict it reaches.
        </Lede>
      </Reveal>

      <div className="mt-14 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {TOOLS.map((t, i) => {
          const Icon = t.icon;
          return (
            <Reveal key={t.name} delay={i * 70} className={t.span}>
              <Card className="flex h-full flex-col p-6">
                <div className="flex items-start justify-between gap-3">
                  <span className="grid size-10 place-items-center rounded-lg border border-white/[0.08] bg-white/[0.03] text-accent">
                    <Icon className="size-5" aria-hidden="true" />
                  </span>
                  <span className="rounded-full border border-white/[0.07] px-2.5 py-1 font-mono text-[10px] text-ink-3">
                    {t.tag}
                  </span>
                </div>
                <h3 className="mt-5 text-lg font-semibold tracking-[-0.02em] text-ink">{t.name}</h3>
                <p className="mt-2 text-sm leading-[1.6] text-ink-2">{t.desc}</p>
                <div className="mt-6 grow" />
                <div className="pt-2">{t.visual}</div>
              </Card>
            </Reveal>
          );
        })}
      </div>
    </Section>
  );
}
