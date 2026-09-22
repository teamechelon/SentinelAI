"use client";

export default function ErrorPage({ reset }: { reset: () => void }) {
  return <div className="panel mx-auto max-w-xl p-6"><div className="tech-label">Runtime fault</div><h1 className="mt-2 text-lg font-semibold">The operations view could not load.</h1><p className="mt-2 text-[12px] text-[var(--text-secondary)]">The baseline data remains unchanged. Retry this view to recover the interface.</p><button onClick={reset} className="control mt-5 border-[var(--accent)] bg-[var(--accent)] px-4 font-semibold text-[#06100f] hover:bg-[var(--accent-strong)]">Retry</button></div>;
}
