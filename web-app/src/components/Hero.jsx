import { useEffect, useRef } from "react";
import { ArrowRight, ShieldCheck, Terminal } from "lucide-react";
import { ButtonGhost, ButtonPrimary, LiveDot, Section } from "./primitives.jsx";

/**
 * Rotating wireframe globe + orbiting threat nodes.
 *
 * Hand-built SVG so there is no charting dependency: the rings are ellipses that
 * counter-rotate, and each node sits on a rotating group. All motion is CSS, so
 * prefers-reduced-motion neutralises it for free.
 */
function GlobeViz() {
  const rings = [0, 30, 60, 90, 120, 150];
  const nodes = [
    { r: 118, dur: "22s", size: 4, tone: "var(--color-accent)" },
    { r: 92, dur: "17s", size: 3, tone: "var(--color-violet)" },
    { r: 140, dur: "31s", size: 3.5, tone: "var(--color-live)" },
    { r: 66, dur: "13s", size: 2.5, tone: "var(--color-accent)" },
  ];

  return (
    <div className="relative mx-auto aspect-square w-full max-w-[30rem]">
      <div
        aria-hidden="true"
        className="absolute inset-[14%] rounded-full bg-accent/15 blur-[70px]"
      />
      <svg
        viewBox="-160 -160 320 320"
        className="relative size-full"
        role="img"
        aria-label="Animated globe showing monitored network nodes"
      >
        <defs>
          <linearGradient id="wire" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#00a3ff" stopOpacity="0.85" />
            <stop offset="100%" stopColor="#7b61ff" stopOpacity="0.25" />
          </linearGradient>
          <radialGradient id="core">
            <stop offset="0%" stopColor="#00a3ff" stopOpacity="0.42" />
            <stop offset="70%" stopColor="#00a3ff" stopOpacity="0.05" />
            <stop offset="100%" stopColor="#00a3ff" stopOpacity="0" />
          </radialGradient>
        </defs>

        <circle r="150" fill="url(#core)" />
        <circle r="150" fill="none" stroke="url(#wire)" strokeWidth="0.75" opacity="0.55" />
        <circle r="112" fill="none" stroke="url(#wire)" strokeWidth="0.5" opacity="0.35" />

        {/* Longitude wires */}
        <g className="animate-spin-slow" style={{ transformOrigin: "center" }}>
          {rings.map((deg) => (
            <ellipse
              key={deg}
              rx="150" ry="150" fill="none"
              stroke="url(#wire)" strokeWidth="0.5" opacity="0.4"
              transform={`rotate(${deg}) scale(${Math.max(0.16, Math.abs(Math.cos((deg * Math.PI) / 180)))} 1)`}
            />
          ))}
        </g>

        {/* Latitude wires, counter-rotating for parallax */}
        <g className="animate-spin-slower" style={{ transformOrigin: "center" }}>
          {[-96, -52, 0, 52, 96].map((y, i) => (
            <ellipse
              key={i} cy={y}
              rx={Math.sqrt(Math.max(0, 150 * 150 - y * y))} ry="17"
              fill="none" stroke="url(#wire)" strokeWidth="0.5" opacity="0.3"
            />
          ))}
        </g>

        {/* Orbiting nodes */}
        {nodes.map((n, i) => (
          <g
            key={i}
            style={{ transformOrigin: "center", animation: `spin ${n.dur} linear infinite ${i % 2 ? "reverse" : ""}` }}
          >
            <circle cx={n.r} cy="0" r={n.size} fill={n.tone}>
              <animate attributeName="opacity" values="1;0.35;1" dur="3.5s" repeatCount="indefinite" />
            </circle>
            <circle cx={n.r} cy="0" r={n.size * 3} fill={n.tone} opacity="0.14" />
          </g>
        ))}
      </svg>
    </div>
  );
}

export default function Hero() {
  const glowRef = useRef(null);
  const frame = useRef(0);

  // Cursor glow. Position is written inside a rAF so a fast mouse cannot queue
  // more style writes than the compositor can flush.
  useEffect(() => {
    const el = glowRef.current;
    if (!el || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    if (window.matchMedia("(hover: none)").matches) return;   // skip on touch

    const onMove = (e) => {
      if (frame.current) return;
      frame.current = requestAnimationFrame(() => {
        frame.current = 0;
        const rect = el.parentElement.getBoundingClientRect();
        el.style.setProperty("--mx", `${e.clientX - rect.left}px`);
        el.style.setProperty("--my", `${e.clientY - rect.top}px`);
        el.style.opacity = "1";
      });
    };
    const onLeave = () => { el.style.opacity = "0"; };

    const parent = el.parentElement;
    parent.addEventListener("pointermove", onMove);
    parent.addEventListener("pointerleave", onLeave);
    return () => {
      parent.removeEventListener("pointermove", onMove);
      parent.removeEventListener("pointerleave", onLeave);
      if (frame.current) cancelAnimationFrame(frame.current);
    };
  }, []);

  return (
    <div id="top" className="relative isolate overflow-hidden pt-28 pb-20 sm:pt-36 md:pb-28">
      {/* Layered background: dot texture, mesh wash, cursor glow */}
      <div aria-hidden="true" className="pointer-events-none absolute inset-0 dot-grid opacity-[0.45]" />
      <div aria-hidden="true" className="pointer-events-none absolute inset-0">
        <div className="absolute -top-52 left-[8%] size-[42rem] rounded-full bg-accent/10 blur-[140px]" />
        <div className="absolute -top-24 right-[2%] size-[34rem] rounded-full bg-violet/10 blur-[130px]" />
      </div>
      <div
        ref={glowRef}
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-500"
        style={{
          background:
            "radial-gradient(380px circle at var(--mx, 50%) var(--my, 30%), rgba(0,163,255,0.10), transparent 72%)",
        }}
      />

      <Section className="relative">
        <div className="grid items-center gap-14 lg:grid-cols-[1.05fr_0.95fr] lg:gap-10">
          <div>
            <a
              href="#evidence"
              className="conic-border mb-7 inline-flex items-center gap-2 rounded-full bg-black px-3.5 py-1.5
                font-mono text-[11px] tracking-tight text-ink-2 transition-colors hover:text-ink"
            >
              <LiveDot />
              v2.0 — live breach intelligence
            </a>

            <h1 className="text-balance text-4xl font-bold leading-[1.02] tracking-[-0.035em] sm:text-5xl md:text-6xl lg:text-[4.1rem]">
              <span className="text-gradient">Recruitment fraud,</span>
              <br />
              <span className="text-gradient-accent">stopped at the door.</span>
            </h1>

            <p className="mt-6 max-w-xl text-pretty text-base leading-[1.65] text-ink-2 sm:text-lg">
              Five AI security tools that catch fake job offers, redact candidate PII under the
              DPDP&nbsp;Act, and check credentials against{" "}
              <span className="font-mono text-ink">17.7&nbsp;billion</span> real breached accounts —
              without the password ever leaving the browser.
            </p>

            <div className="mt-9 flex flex-col gap-3 sm:flex-row sm:items-center">
              <ButtonPrimary href="/console">
                Open the console
                <ArrowRight className="size-4 transition-transform duration-300 group-hover:translate-x-0.5" aria-hidden="true" />
              </ButtonPrimary>
              <ButtonGhost href="#api">
                <Terminal className="size-4" aria-hidden="true" />
                Read the API
              </ButtonGhost>
            </div>

            <p className="mt-7 flex flex-wrap items-center gap-x-2.5 gap-y-1 font-mono text-xs text-ink-3">
              <ShieldCheck className="size-3.5 text-live" aria-hidden="true" />
              85 tests passing
              <span aria-hidden="true">·</span> 100% on labelled cases
              <span aria-hidden="true">·</span> zero network calls in CI
            </p>
          </div>

          <div className="animate-float">
            <GlobeViz />
          </div>
        </div>
      </Section>
    </div>
  );
}
