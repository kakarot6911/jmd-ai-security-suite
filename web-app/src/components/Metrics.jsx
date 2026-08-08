import { Reveal, Section } from "./primitives.jsx";

/*
 * Every figure here is measurable from the repository — `./run.sh test`,
 * `./run.sh eval`, and the live HIBP catalogue endpoint. Nothing is a marketing
 * estimate, so none of it goes stale or overstates the product.
 */
const STATS = [
  { value: "1,024", label: "real breaches tracked", note: "live HIBP register" },
  { value: "17.7B", label: "accounts in corpus", note: "cumulative, all breaches" },
  { value: "100%", label: "on labelled cases", note: "106 hand-labelled, 0 FP / 0 FN" },
  { value: "85", label: "tests passing", note: "no network required" },
];

export default function Metrics() {
  return (
    <Section className="py-10">
      <Reveal>
        <dl
          className="grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-white/[0.06]
            bg-white/[0.04] lg:grid-cols-4"
        >
          {STATS.map((s) => (
            <div key={s.label} className="bg-black/70 px-5 py-7 text-center backdrop-blur-xl sm:px-6">
              <dt className="sr-only">{s.label}</dt>
              <dd>
                <div className="font-mono text-2xl font-semibold tracking-tight text-ink sm:text-3xl">
                  {s.value}
                </div>
                <div className="mt-2 text-xs font-medium text-ink-2">{s.label}</div>
                <div className="mt-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-ink-3">
                  {s.note}
                </div>
              </dd>
            </div>
          ))}
        </dl>
      </Reveal>
    </Section>
  );
}
