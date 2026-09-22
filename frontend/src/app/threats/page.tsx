import type { Metadata } from "next";
import { ThreatFilterBar } from "@/components/threats/threat-filter-bar";
import { ThreatQueue } from "@/components/threats/threat-queue";
import { getSentinelDataSource } from "@/data/data-source";
import { parseRiskFilter, parseStatusFilter } from "@/data/threat-query";

export const metadata: Metadata = { title: "Threat Queue" };

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

function scalar(value: string | string[] | undefined) { return Array.isArray(value) ? value[0] : value; }

export default async function ThreatsPage({ searchParams }: { searchParams: SearchParams }) {
  const params = await searchParams;
  const q = scalar(params.q) ?? "";
  const risk = parseRiskFilter(scalar(params.risk));
  const status = parseStatusFilter(scalar(params.status));
  const focus = scalar(params.focus);
  const source = getSentinelDataSource();
  const [threats, counts] = await Promise.all([source.listThreats({ q, risk, status }), source.getCounts()]);
  const total = counts.alerts;

  return (
    <div className="mx-auto max-w-[1600px] space-y-5">
      <section className="flex flex-col gap-4 border-b border-border pb-5 md:flex-row md:items-end md:justify-between">
        <div><div className="tech-label">Sentinel / Triage</div><h1 className="mt-2 text-[24px] font-bold tracking-[-0.03em]">Alert Investigation</h1><p className="mt-1 text-[12px] text-[var(--text-secondary)]">Prioritised alerts with explainable evidence and investigation context.</p></div>
        <div aria-live="polite" className="font-mono text-[11px] text-[var(--text-muted)]"><span className="text-foreground">{threats.length}</span> / {total} alerts</div>
      </section>

      <ThreatFilterBar q={q} risk={risk} status={status} />
      <ThreatQueue threats={threats} focusedId={focus} />
    </div>
  );
}
