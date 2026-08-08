import { useEffect, useRef, useState } from "react";

/**
 * Reveals children once they scroll into view.
 *
 * Uses IntersectionObserver rather than a scroll handler so there is no
 * per-frame work on the main thread, and unobserves immediately after firing so
 * a revealed section costs nothing for the rest of the session.
 */
export function Reveal({ children, delay = 0, className = "", as: Tag = "div" }) {
  const ref = useRef(null);
  const [shown, setShown] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (typeof IntersectionObserver === "undefined") {
      setShown(true);                       // no observer support: show immediately
      return;
    }
    const io = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setShown(true);
          io.unobserve(el);
        }
      },
      { rootMargin: "0px 0px -12% 0px", threshold: 0.05 }
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);

  return (
    <Tag
      ref={ref}
      style={shown ? { animationDelay: `${delay}ms` } : undefined}
      className={`${shown ? "animate-rise" : "opacity-0"} ${className}`}
    >
      {children}
    </Tag>
  );
}

/** Standard section wrapper: max width, vertical rhythm, optional id for nav. */
export function Section({ id, children, className = "" }) {
  return (
    <section id={id} className={`relative mx-auto w-full max-w-7xl px-5 sm:px-8 ${className}`}>
      {children}
    </section>
  );
}

/** Small uppercase label that precedes a section headline. */
export function Eyebrow({ children, tone = "accent" }) {
  const dot = tone === "live" ? "bg-live" : "bg-accent";
  return (
    <div className="mb-4 inline-flex items-center gap-2.5 font-mono text-[11px] font-medium uppercase tracking-[0.18em] text-ink-2">
      <span className={`inline-block size-1.5 rounded-full ${dot}`} aria-hidden="true" />
      {children}
    </div>
  );
}

export function SectionHeading({ children, className = "" }) {
  return (
    <h2
      className={`text-balance text-3xl font-semibold leading-[1.1] tracking-[-0.03em] text-ink sm:text-4xl md:text-5xl ${className}`}
    >
      {children}
    </h2>
  );
}

export function Lede({ children, className = "" }) {
  return (
    <p className={`mt-5 max-w-2xl text-pretty text-base leading-[1.65] text-ink-2 ${className}`}>
      {children}
    </p>
  );
}

/** Glassmorphism-lite card. `glow` adds the accent halo used on hover. */
export function Card({ children, className = "", glow = true, as: Tag = "div", ...rest }) {
  return (
    <Tag
      {...rest}
      className={`group relative overflow-hidden rounded-xl border border-white/[0.06] bg-white/[0.02] backdrop-blur-xl
        transition-all duration-300 ease-out
        hover:border-white/[0.12] hover:bg-white/[0.035]
        ${glow ? "hover:shadow-[0_0_60px_-15px_rgba(0,163,255,0.3)]" : ""} ${className}`}
    >
      {children}
    </Tag>
  );
}

/** Primary filled CTA. Renders as <a> so it stays keyboard- and SEO-friendly. */
export function ButtonPrimary({ href, children, className = "", shimmer = false, ...rest }) {
  return (
    <a
      href={href}
      {...rest}
      className={`group relative inline-flex items-center justify-center gap-2 overflow-hidden rounded-lg
        bg-accent px-5 py-3 text-sm font-semibold text-black
        shadow-[0_0_40px_-12px_rgba(0,163,255,0.75)]
        transition-all duration-300 ease-out hover:scale-[1.02] hover:bg-[#33b6ff]
        hover:shadow-[0_0_60px_-10px_rgba(0,163,255,0.9)] active:scale-[0.99] ${className}`}
    >
      <span className="relative z-10 inline-flex items-center gap-2">{children}</span>
      {shimmer && (
        <span
          aria-hidden="true"
          className="pointer-events-none absolute inset-y-0 -left-1/3 w-1/3 skew-x-[-20deg]
            bg-white/30 blur-md animate-shimmer"
        />
      )}
    </a>
  );
}

/** Ghost CTA — border only, for the secondary action. */
export function ButtonGhost({ href, children, className = "", ...rest }) {
  return (
    <a
      href={href}
      {...rest}
      className={`inline-flex items-center justify-center gap-2 rounded-lg border border-white/[0.10]
        bg-white/[0.02] px-5 py-3 text-sm font-medium text-ink-2 backdrop-blur-xl
        transition-all duration-300 ease-out hover:scale-[1.02] hover:border-white/20
        hover:bg-white/[0.05] hover:text-ink active:scale-[0.99] ${className}`}
    >
      {children}
    </a>
  );
}

/** Off-centre radial wash placed behind a section. Purely decorative. */
export function GradientMesh({ className = "", from = "rgba(0,163,255,0.10)", to = "rgba(123,97,255,0.08)" }) {
  return (
    <div aria-hidden="true" className={`pointer-events-none absolute inset-0 overflow-hidden ${className}`}>
      <div
        className="absolute -top-40 left-[12%] size-[36rem] rounded-full blur-[120px]"
        style={{ background: from }}
      />
      <div
        className="absolute -bottom-52 right-[6%] size-[32rem] rounded-full blur-[130px]"
        style={{ background: to }}
      />
    </div>
  );
}

/** Live status pip with an expanding halo. */
export function LiveDot({ className = "" }) {
  return (
    <span className={`relative inline-flex size-2 shrink-0 ${className}`} aria-hidden="true">
      <span className="absolute inset-0 rounded-full bg-live animate-pulse-ring" />
      <span className="relative inline-flex size-2 rounded-full bg-live" />
    </span>
  );
}
