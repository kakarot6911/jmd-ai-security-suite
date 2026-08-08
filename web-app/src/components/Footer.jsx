import { GithubIcon, LinkedinIcon } from "./BrandIcons.jsx";

const COLUMNS = [
  {
    title: "Product",
    links: [
      { label: "Console", href: "/console" },
      { label: "API docs", href: "/docs" },
      { label: "Capabilities", href: "#capabilities" },
      { label: "Architecture", href: "#architecture" },
    ],
  },
  {
    title: "Tools",
    links: [
      { label: "PhishGuard", href: "/console#phishguard" },
      { label: "ResumeShield", href: "/console#resumeshield" },
      { label: "LinkGuard", href: "/console#linkguard" },
      { label: "BreachRadar", href: "/console#breachradar" },
    ],
  },
  {
    title: "Resources",
    links: [
      { label: "Health check", href: "/health" },
      { label: "Version", href: "/version" },
      { label: "Evidence", href: "#evidence" },
      { label: "Source", href: "https://github.com/kakarot6911/jmd-ai-security-suite" },
    ],
  },
  {
    title: "Legal",
    links: [
      { label: "MIT licence", href: "https://github.com/kakarot6911/jmd-ai-security-suite/blob/main/LICENSE" },
      { label: "DPDP Act 2023", href: "#capabilities" },
      { label: "Responsible use", href: "#architecture" },
    ],
  },
];

export default function Footer() {
  return (
    <footer className="relative border-t border-white/[0.06] bg-black">
      <div className="mx-auto max-w-7xl px-5 py-16 sm:px-8">
        <div className="grid gap-10 sm:grid-cols-2 lg:grid-cols-5">
          <div className="lg:col-span-1">
            <div className="flex items-center gap-2 font-mono text-sm font-semibold text-ink">
              JMD<span className="text-ink-3">/</span>SECURITY
              <span className="inline-block size-1.5 rounded-full bg-accent" aria-hidden="true" />
            </div>
            <p className="mt-3 max-w-[22ch] text-xs leading-[1.7] text-ink-3">
              AI security tooling for recruitment — built for JMD The Career Maker.
            </p>
          </div>

          {COLUMNS.map((col) => (
            <nav key={col.title} aria-label={col.title}>
              <h3 className="font-mono text-[11px] uppercase tracking-[0.14em] text-ink-2">{col.title}</h3>
              <ul className="mt-4 space-y-2.5">
                {col.links.map((l) => (
                  <li key={l.label}>
                    <a
                      href={l.href}
                      className="text-xs text-ink-3 transition-colors duration-200 hover:text-ink"
                      {...(l.href.startsWith("http") ? { target: "_blank", rel: "noreferrer noopener" } : {})}
                    >
                      {l.label}
                    </a>
                  </li>
                ))}
              </ul>
            </nav>
          ))}
        </div>

        <div className="mt-14 flex flex-col items-center justify-between gap-4 border-t border-white/[0.06] pt-7 sm:flex-row">
          <p className="text-xs text-ink-3">
            © {new Date().getFullYear()} JMD Security Suite · MIT licensed
          </p>
          <div className="flex items-center gap-2">
            <a
              href="https://github.com/kakarot6911/jmd-ai-security-suite"
              aria-label="GitHub repository" target="_blank" rel="noreferrer noopener"
              className="grid size-8 place-items-center rounded-lg border border-white/[0.06] text-ink-3 transition-colors hover:border-white/15 hover:text-ink"
            >
              <GithubIcon className="size-3.5" />
            </a>
            <a
              href="https://www.linkedin.com/" aria-label="LinkedIn"
              target="_blank" rel="noreferrer noopener"
              className="grid size-8 place-items-center rounded-lg border border-white/[0.06] text-ink-3 transition-colors hover:border-white/15 hover:text-ink"
            >
              <LinkedinIcon className="size-3.5" />
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}
