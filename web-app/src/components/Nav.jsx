import { useEffect, useState } from "react";
import { Menu, X, ArrowUpRight } from "lucide-react";

const LINKS = [
  { href: "#capabilities", label: "Capabilities" },
  { href: "#api", label: "API" },
  { href: "#architecture", label: "Architecture" },
  { href: "#evidence", label: "Evidence" },
];

export default function Nav() {
  const [open, setOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const [active, setActive] = useState("");

  // Solidify the bar only after the hero starts moving under it.
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 12);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  // Highlight the section currently in view. One observer for all sections
  // rather than a scroll handler doing getBoundingClientRect per frame.
  useEffect(() => {
    const sections = LINKS.map((l) => document.querySelector(l.href)).filter(Boolean);
    if (!sections.length || typeof IntersectionObserver === "undefined") return;
    const io = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
        if (visible) setActive(`#${visible.target.id}`);
      },
      { rootMargin: "-45% 0px -50% 0px", threshold: [0, 0.25, 0.5] }
    );
    sections.forEach((s) => io.observe(s));
    return () => io.disconnect();
  }, []);

  // Lock page scroll while the mobile sheet is open.
  useEffect(() => {
    document.body.style.overflow = open ? "hidden" : "";
    return () => { document.body.style.overflow = ""; };
  }, [open]);

  useEffect(() => {
    const onKey = (e) => e.key === "Escape" && setOpen(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <header
      className={`fixed inset-x-0 top-0 z-50 h-16 transition-colors duration-300 ${
        scrolled ? "border-b border-white/[0.06] bg-black/60 backdrop-blur-md" : "border-b border-transparent"
      }`}
    >
      <nav
        aria-label="Primary"
        className="mx-auto flex h-16 max-w-7xl items-center justify-between gap-6 px-5 sm:px-8"
      >
        <a href="#top" className="flex shrink-0 items-center gap-2 font-mono text-sm font-semibold tracking-tight text-ink">
          JMD<span className="text-ink-3">/</span>SECURITY
          <span className="inline-block size-1.5 rounded-full bg-accent shadow-[0_0_10px_2px_rgba(0,163,255,0.8)]" aria-hidden="true" />
        </a>

        <ul className="hidden items-center gap-1 md:flex">
          {LINKS.map((l) => {
            const isActive = active === l.href;
            return (
              <li key={l.href}>
                <a
                  href={l.href}
                  aria-current={isActive ? "true" : undefined}
                  className={`relative px-3.5 py-2 text-sm transition-colors duration-200 ${
                    isActive ? "text-ink" : "text-ink-2 hover:text-ink"
                  }`}
                >
                  {l.label}
                  <span
                    aria-hidden="true"
                    className={`absolute inset-x-3 -bottom-px h-px origin-center bg-accent transition-transform duration-300 ease-out ${
                      isActive ? "scale-x-100 shadow-[0_0_8px_1px_rgba(0,163,255,0.9)]" : "scale-x-0"
                    }`}
                  />
                </a>
              </li>
            );
          })}
        </ul>

        <div className="flex items-center gap-2">
          <a
            href="/console"
            className="conic-border hidden rounded-lg bg-black px-4 py-2 text-sm font-medium text-ink
              transition-transform duration-300 ease-out hover:scale-[1.03] sm:inline-flex sm:items-center sm:gap-1.5"
          >
            Open console
            <ArrowUpRight className="size-3.5" aria-hidden="true" />
          </a>
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            aria-controls="mobile-menu"
            aria-label={open ? "Close menu" : "Open menu"}
            className="grid size-9 place-items-center rounded-lg border border-white/[0.08] text-ink-2
              transition-colors hover:text-ink md:hidden"
          >
            {open ? <X className="size-4" /> : <Menu className="size-4" />}
          </button>
        </div>
      </nav>

      {/* Mobile sheet */}
      <div
        id="mobile-menu"
        hidden={!open}
        className="border-b border-white/[0.06] bg-black/95 backdrop-blur-xl md:hidden"
      >
        <ul className="mx-auto max-w-7xl px-5 py-3">
          {LINKS.map((l) => (
            <li key={l.href}>
              <a
                href={l.href}
                onClick={() => setOpen(false)}
                className="block rounded-lg px-3 py-3 text-sm text-ink-2 transition-colors hover:bg-white/[0.04] hover:text-ink"
              >
                {l.label}
              </a>
            </li>
          ))}
          <li>
            <a
              href="/console"
              className="mt-1 block rounded-lg bg-accent px-3 py-3 text-center text-sm font-semibold text-black"
            >
              Open console
            </a>
          </li>
        </ul>
      </div>
    </header>
  );
}
