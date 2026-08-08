import { useState } from "react";
import { Check, Copy, Lock, Sparkles, Zap } from "lucide-react";
import { Eyebrow, Lede, Reveal, Section, SectionHeading } from "./primitives.jsx";

/* Tiny token-based highlighter — a full syntax engine is far more weight than a
   handful of snippets justifies, and this keeps the bundle dependency-free. */
const RULES = [
  [/(#.*$)/gm, "text-ink-3 italic"],
  [/(".*?")/g, "text-[#7ee787]"],
  [/(\b\d+\.?\d*\b)/g, "text-[#79c0ff]"],
  [/\b(curl|import|const|await|fetch|from|def|print|method|POST|GET)\b/g, "text-violet"],
  [/(-X|-H|-d|--data)\b/g, "text-accent"],
];

function highlight(code) {
  const escaped = code
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return RULES.reduce(
    (acc, [re, cls]) => acc.replace(re, (m) => `<span class="${cls}">${m}</span>`),
    escaped
  );
}

const TABS = [
  {
    id: "curl", label: "cURL", file: "check-link.sh",
    code: `# Analyse a suspicious job link
curl -X POST http://localhost:8000/linkguard/analyze \\
  -H "Content-Type: application/json" \\
  -d '{"url": "https://jmdcaremaker.com/login"}'

# => verdict "DANGEROUS", risk_score 100
#    signal: brand_typosquat (1 edit from the real domain)`,
  },
  {
    id: "python", label: "Python", file: "screen.py",
    code: `from linkguard.engine import analyze_url

v = analyze_url("https://jmdcaremaker.com/login")

print(v.verdict)        # DANGEROUS
print(v.risk_score)     # 100
for s in v.signals:
    print(s.severity, s.name, s.detail)`,
  },
  {
    id: "node", label: "Node.js", file: "pwned.mjs",
    code: `# The password never leaves the browser: only the first
# 5 hex chars of its SHA-1 are sent upstream.
const hash = await sha1(password);
const res = await fetch(
  "/breachradar/range/" + hash.slice(0, 5)
);
const seen = match(await res.text(), hash.slice(5));
# "password123" => 2266543 real sightings`,
  },
];

const POINTS = [
  { icon: Zap, title: "One adapter, no drift", body: "The console and the REST API call the same integration layer, so a fix lands in both or neither." },
  { icon: Lock, title: "Hardened by default", body: "Constant-time key auth, sliding-window rate limits, body caps and a strict CSP — all environment-driven." },
  { icon: Sparkles, title: "Explainable output", body: "Every verdict ships the concrete signals behind it. No score arrives without its evidence." },
];

export default function CodeShowcase() {
  const [tab, setTab] = useState(TABS[0].id);
  const [copied, setCopied] = useState(false);
  const active = TABS.find((t) => t.id === tab) ?? TABS[0];

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(active.code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch { /* clipboard blocked — the code is selectable anyway */ }
  };

  return (
    <Section id="api" className="py-24 md:py-32">
      <div className="grid items-center gap-14 lg:grid-cols-2 lg:gap-16">
        <Reveal>
          <Eyebrow>Developer surface</Eyebrow>
          <SectionHeading>A REST API you can read in one sitting.</SectionHeading>
          <Lede>
            Nine endpoints, OpenAPI docs at <code className="font-mono text-ink">/docs</code>, and
            no client library to install. Everything the console does, your scripts can do.
          </Lede>

          <ul className="mt-9 space-y-5">
            {POINTS.map((p) => {
              const Icon = p.icon;
              return (
                <li key={p.title} className="flex gap-4">
                  <span className="mt-0.5 grid size-8 shrink-0 place-items-center rounded-lg border border-accent/25 bg-accent/10 text-accent">
                    <Icon className="size-4" aria-hidden="true" />
                  </span>
                  <div>
                    <div className="text-sm font-semibold text-ink">{p.title}</div>
                    <div className="mt-1 text-sm leading-[1.6] text-ink-2">{p.body}</div>
                  </div>
                </li>
              );
            })}
          </ul>
        </Reveal>

        <Reveal delay={120}>
          <div className="overflow-hidden rounded-xl border border-white/[0.08] bg-[#0a0a0a] shadow-[0_0_80px_-30px_rgba(0,163,255,0.45)]">
            {/* macOS-style chrome */}
            <div className="flex items-center gap-3 border-b border-white/[0.06] bg-white/[0.02] px-4 py-3">
              <div className="flex gap-1.5" aria-hidden="true">
                <span className="size-3 rounded-full bg-[#ff5f57]" />
                <span className="size-3 rounded-full bg-[#febc2e]" />
                <span className="size-3 rounded-full bg-[#28c840]" />
              </div>
              <span className="ml-1 font-mono text-xs text-ink-3">{active.file}</span>
              <button
                type="button" onClick={copy}
                aria-label={copied ? "Copied" : "Copy code"}
                className="ml-auto grid size-7 place-items-center rounded-md border border-white/[0.08]
                  text-ink-3 transition-colors hover:text-ink"
              >
                {copied ? <Check className="size-3.5 text-live" /> : <Copy className="size-3.5" />}
              </button>
            </div>

            {/* Tabs */}
            <div role="tablist" aria-label="Language" className="flex border-b border-white/[0.06] bg-black/40">
              {TABS.map((t) => (
                <button
                  key={t.id} type="button" role="tab"
                  aria-selected={tab === t.id}
                  onClick={() => setTab(t.id)}
                  className={`relative px-4 py-2.5 font-mono text-xs transition-colors ${
                    tab === t.id ? "text-ink" : "text-ink-3 hover:text-ink-2"
                  }`}
                >
                  {t.label}
                  {tab === t.id && (
                    <span aria-hidden="true" className="absolute inset-x-2 -bottom-px h-px bg-accent shadow-[0_0_8px_1px_rgba(0,163,255,0.8)]" />
                  )}
                </button>
              ))}
            </div>

            {/* Code with line numbers */}
            <div className="overflow-x-auto">
              <table className="w-full border-collapse font-mono text-[12.5px] leading-[1.75]">
                <tbody>
                  {active.code.split("\n").map((line, i) => (
                    <tr key={i}>
                      <td className="w-10 select-none border-r border-white/[0.05] px-2 py-0 text-right align-top text-ink-3/70">
                        {i + 1}
                      </td>
                      <td
                        className="whitespace-pre px-4 py-0 text-ink-2"
                        dangerouslySetInnerHTML={{ __html: highlight(line) || "&nbsp;" }}
                      />
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </Reveal>
      </div>
    </Section>
  );
}
