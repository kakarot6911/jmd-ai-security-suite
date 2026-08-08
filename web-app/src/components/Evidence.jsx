import { Card, Eyebrow, Lede, Reveal, Section, SectionHeading } from "./primitives.jsx";

/*
 * This slot is where a marketing template puts a customer logo cloud and
 * testimonials. Inventing either for a real product would be fabricating
 * endorsements, so it shows two things that are actually true instead: the
 * stack it genuinely runs on, and two results reproducible from the repo.
 */
const STACK = [
  "Python 3.14", "FastAPI", "scikit-learn", "React 19",
  "Tailwind v4", "Docker", "Have I Been Pwned", "Streamlit",
];

const RESULTS = [
  {
    quote:
      "A verdict with an empty red-flag list cannot be justified to a candidate, so it is no longer issued. The model score is capped below the fraud threshold when no deterministic rule fires.",
    metric: "76.9% → 100%",
    label: "PhishGuard accuracy on labelled cases",
    detail: "3 false positives eliminated, no loss of recall",
  },
  {
    quote:
      "The browser hashes the password and sends only the first five hex characters of the SHA-1 upstream. Neither this server nor HIBP can determine which password was tested.",
    metric: "2,266,543",
    label: "real sightings returned for “password123”",
    detail: "k-anonymity against the live Pwned Passwords range API",
  },
];

export default function Evidence() {
  return (
    <Section id="evidence" className="py-24 md:py-32">
      <Reveal className="max-w-2xl">
        <Eyebrow tone="live">Verifiable</Eyebrow>
        <SectionHeading>Claims you can re-run yourself.</SectionHeading>
        <Lede>
          Accuracy here is measured, not asserted. Every number below comes from a command in the
          repository, and the labelled cases that produce them ship with the source.
        </Lede>
      </Reveal>

      {/* Stack row — the marquee is decorative and duplicated for a seamless loop. */}
      <Reveal delay={80} className="mt-14">
        <div className="mask-fade-x overflow-hidden">
          <ul className="flex w-max animate-marquee items-center gap-3" aria-label="Built with">
            {[...STACK, ...STACK].map((name, i) => (
              <li
                key={`${name}-${i}`}
                aria-hidden={i >= STACK.length ? "true" : undefined}
                className="shrink-0 rounded-lg border border-white/[0.06] bg-white/[0.02] px-4 py-2.5
                  font-mono text-xs text-ink-3 opacity-50 transition-opacity duration-300 hover:opacity-100"
              >
                {name}
              </li>
            ))}
          </ul>
        </div>
      </Reveal>

      <div className="mt-12 grid gap-4 md:grid-cols-2">
        {RESULTS.map((r, i) => (
          <Reveal key={r.label} delay={i * 110}>
            <Card className="flex h-full flex-col p-7">
              <blockquote className="text-pretty text-[15px] leading-[1.7] text-ink-2">
                <p>“{r.quote}”</p>
              </blockquote>
              <div className="mt-7 border-t border-white/[0.06] pt-5">
                <div className="font-mono text-2xl font-semibold text-live">{r.metric}</div>
                <div className="mt-1.5 text-sm font-medium text-ink">{r.label}</div>
                <div className="mt-0.5 font-mono text-[11px] text-ink-3">{r.detail}</div>
              </div>
            </Card>
          </Reveal>
        ))}
      </div>

      <Reveal delay={200} className="mt-8">
        <p className="text-center font-mono text-xs text-ink-3">
          Reproduce:{" "}
          <span className="text-ink-2">./run.sh eval</span> ·{" "}
          <span className="text-ink-2">./run.sh holdout</span> ·{" "}
          <span className="text-ink-2">./run.sh fuzz</span>
        </p>
      </Reveal>
    </Section>
  );
}
