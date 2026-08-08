import { Suspense, lazy } from "react";
import Nav from "./components/Nav.jsx";
import Hero from "./components/Hero.jsx";
import Metrics from "./components/Metrics.jsx";

/*
 * Everything below the fold is code-split. Nav + Hero + Metrics are what the
 * first paint needs; the rest arrives as separate chunks while the user reads.
 */
const Bento = lazy(() => import("./components/Bento.jsx"));
const CodeShowcase = lazy(() => import("./components/CodeShowcase.jsx"));
const Architecture = lazy(() => import("./components/Architecture.jsx"));
const Evidence = lazy(() => import("./components/Evidence.jsx"));
const CTA = lazy(() => import("./components/CTA.jsx"));
const Footer = lazy(() => import("./components/Footer.jsx"));

/* Reserves height so a chunk arriving mid-scroll cannot shift the layout. */
function Placeholder({ h = "28rem" }) {
  return <div aria-hidden="true" style={{ minHeight: h }} />;
}

export default function App() {
  return (
    <>
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[60]
          focus:rounded-lg focus:border focus:border-accent focus:bg-black focus:px-4 focus:py-2.5
          focus:text-sm focus:font-semibold focus:text-ink"
      >
        Skip to content
      </a>

      <Nav />

      <main id="main">
        <Hero />
        <Metrics />

        <Suspense fallback={<Placeholder h="40rem" />}>
          <Bento />
          <CodeShowcase />
          <Architecture />
          <Evidence />
          <CTA />
        </Suspense>
      </main>

      <Suspense fallback={<Placeholder h="20rem" />}>
        <Footer />
      </Suspense>
    </>
  );
}
