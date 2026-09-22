import type { Metadata } from "next";
import Link from "next/link";
import { ArrowLeft, Clock3 } from "lucide-react";
import { notFound } from "next/navigation";
import { getPlannedModule, plannedModules } from "@/config/navigation";

export const metadata: Metadata = { title: "Planned module" };

export function generateStaticParams() {
  return plannedModules.map(({ slug }) => ({ module: slug }));
}

export default async function PlannedModulePage({ params }: { params: Promise<{ module: string }> }) {
  const { module: slug } = await params;
  const plannedModule = getPlannedModule(slug);

  if (!plannedModule) notFound();

  return (
    <div className="mx-auto max-w-[1600px] space-y-5">
      <section className="border-b border-border pb-5">
        <div className="tech-label">Sentinel / Frontend migration</div>
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <h1 className="text-[22px] font-semibold tracking-[-0.025em]">{plannedModule.label}</h1>
          <span className="rounded-sm border border-[var(--border-strong)] px-2 py-1 font-mono text-[9px] font-semibold tracking-[0.1em] text-[var(--text-muted)]">
            PLANNED
          </span>
        </div>
        <p className="mt-1 text-[12px] text-[var(--text-secondary)]">This module is not yet migrated to the Next.js frontend.</p>
      </section>

      <section aria-labelledby="migration-status" className="panel max-w-2xl p-5">
        <div className="flex items-start gap-3">
          <Clock3 aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-[var(--text-muted)]" />
          <div>
            <h2 id="migration-status" className="text-[13px] font-semibold">Module pending migration</h2>
            <p className="mt-2 max-w-xl text-[12px] leading-5 text-[var(--text-secondary)]">
              The existing Streamlit implementation remains the functional reference for this module. No replacement functionality is exposed here yet.
            </p>
            <Link href="/" className="mt-4 inline-flex items-center gap-1.5 rounded-sm text-[11px] font-medium text-[var(--accent-strong)] hover:text-foreground">
              <ArrowLeft aria-hidden="true" className="size-3" /> Return to overview
            </Link>
          </div>
        </div>
      </section>
    </div>
  );
}
