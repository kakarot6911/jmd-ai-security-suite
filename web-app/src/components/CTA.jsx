import { ArrowRight } from "lucide-react";
import { GithubIcon } from "./BrandIcons.jsx";
import { ButtonGhost, ButtonPrimary, Reveal, Section } from "./primitives.jsx";

export default function CTA() {
  return (
    <div className="relative isolate overflow-hidden py-24 md:py-32">
      <div aria-hidden="true" className="pointer-events-none absolute inset-0">
        <div className="absolute left-1/2 top-1/2 size-[46rem] -translate-x-1/2 -translate-y-1/2 rounded-full bg-accent/[0.09] blur-[150px]" />
        <div className="absolute left-1/2 top-1/2 size-[28rem] -translate-x-1/2 -translate-y-1/2 rounded-full bg-violet/[0.09] blur-[120px]" />
      </div>
      <div aria-hidden="true" className="pointer-events-none absolute inset-0 dot-grid opacity-30" />

      <Section className="relative text-center">
        <Reveal>
          <h2 className="mx-auto max-w-3xl text-balance text-4xl font-semibold leading-[1.05] tracking-[-0.035em] sm:text-5xl md:text-6xl">
            <span className="text-gradient">Start screening today.</span>
          </h2>
          <p className="mx-auto mt-6 max-w-xl text-pretty text-base leading-[1.65] text-ink-2">
            Clone it, run one command, and the whole suite is live on localhost — website, REST API
            and all five tools.
          </p>

          <div className="mt-10 flex flex-col items-center justify-center gap-3 sm:flex-row">
            <ButtonPrimary href="/console" shimmer className="px-7 py-3.5 text-[15px]">
              Open the console
              <ArrowRight className="size-4 transition-transform duration-300 group-hover:translate-x-0.5" aria-hidden="true" />
            </ButtonPrimary>
            <ButtonGhost
              href="https://github.com/kakarot6911/jmd-ai-security-suite"
              className="px-7 py-3.5 text-[15px]"
              target="_blank" rel="noreferrer noopener"
            >
              <GithubIcon className="size-4" />
              View source
            </ButtonGhost>
          </div>

          <p className="mt-8 font-mono text-xs text-ink-3">
            MIT licensed <span aria-hidden="true">·</span> No account required{" "}
            <span aria-hidden="true">·</span> Runs fully offline
          </p>
        </Reveal>
      </Section>
    </div>
  );
}
