import { Binary, ScanLine, ShieldCheck } from "lucide-react";
import { Eyebrow, Lede, Reveal, Section, SectionHeading } from "./primitives.jsx";

const STEPS = [
  {
    icon: ScanLine, n: "01", title: "Ingest",
    body: "A message, resume, link or address arrives — from the console, the API, or a script.",
  },
  {
    icon: Binary, n: "02", title: "Analyse",
    body: "Deterministic rules run first and carry the weight; the trained model refines, never decides alone.",
  },
  {
    icon: ShieldCheck, n: "03", title: "Explain",
    body: "A verdict, a score, and the exact signals behind it — auditable by a human, every time.",
  },
];

/** Animated dashed connector drawn between the three steps on wide screens. */
function Connector() {
  return (
    <svg
      aria-hidden="true"
      className="pointer-events-none absolute inset-x-0 top-[2.15rem] hidden h-px w-full md:block"
      preserveAspectRatio="none" viewBox="0 0 100 1"
    >
      <line
        x1="0" y1="0.5" x2="100" y2="0.5"
        stroke="url(#flow)" strokeWidth="1"
        strokeDasharray="4 4" className="animate-dash"
      />
      <defs>
        <linearGradient id="flow" x1="0" x2="1">
          <stop offset="0%" stopColor="#00a3ff" stopOpacity="0" />
          <stop offset="20%" stopColor="#00a3ff" stopOpacity="0.7" />
          <stop offset="80%" stopColor="#7b61ff" stopOpacity="0.7" />
          <stop offset="100%" stopColor="#7b61ff" stopOpacity="0" />
        </linearGradient>
      </defs>
    </svg>
  );
}

export default function Architecture() {
  return (
    <div className="relative isolate overflow-hidden">
      <div aria-hidden="true" className="pointer-events-none absolute inset-0 blueprint opacity-40" />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0"
        style={{ background: "radial-gradient(60% 50% at 50% 0%, rgba(0,163,255,0.07), transparent 70%)" }}
      />

      <Section id="architecture" className="py-24 md:py-32">
        <Reveal className="max-w-2xl">
          <Eyebrow>How it works</Eyebrow>
          <SectionHeading>Evidence first, model second.</SectionHeading>
          <Lede>
            The classifier is trained on synthetic data, so it is treated as a refinement rather
            than an oracle. With no rule fired, the score is capped below the fraud line — a
            verdict you cannot justify is a verdict this system will not issue.
          </Lede>
        </Reveal>

        <div className="relative mt-16 grid gap-10 md:grid-cols-3 md:gap-8">
          <Connector />
          {STEPS.map((s, i) => {
            const Icon = s.icon;
            return (
              <Reveal key={s.n} delay={i * 130} className="relative">
                <div className="flex items-center gap-4">
                  <span
                    className="grid size-[4.3rem] shrink-0 place-items-center rounded-full border border-accent/30
                      bg-black text-accent shadow-[0_0_40px_-12px_rgba(0,163,255,0.7)]"
                  >
                    <Icon className="size-6" aria-hidden="true" />
                  </span>
                  <span className="font-mono text-3xl font-semibold text-white/[0.09]">{s.n}</span>
                </div>
                <h3 className="mt-6 text-lg font-semibold tracking-[-0.02em] text-ink">{s.title}</h3>
                <p className="mt-2 max-w-xs text-sm leading-[1.65] text-ink-2">{s.body}</p>
              </Reveal>
            );
          })}
        </div>
      </Section>
    </div>
  );
}
