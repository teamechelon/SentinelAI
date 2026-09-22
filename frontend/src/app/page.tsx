import Link from "next/link";
import { ChevronRight } from "lucide-react";
import { AnomalyActivityChart, RiskActivityChart } from "@/components/charts/activity-charts";
import { CompactStat } from "@/components/system/compact-stat";
import { SectionHeading } from "@/components/system/section-heading";
import { ThreatQueue } from "@/components/threats/threat-queue";
import { getSentinelDataSource } from "@/data/data-source";

export default async function OverviewPage() {
  const source = getSentinelDataSource();
  const [overview, allThreats, system, counts] = await Promise.all([source.getOverview(), source.listThreats(), source.getSystemStatus(), source.getCounts()]);
  const threats = allThreats.slice(0, 10);
  const firstDay = overview.riskActivity.at(0)?.date;
  const lastDay = overview.riskActivity.at(-1)?.date;

  return (
    <div className="mx-auto max-w-[1600px] space-y-6">
      <section className="flex flex-col gap-5 border-b border-border pb-5 xl:flex-row xl:items-end xl:justify-between">
        <div><div className="tech-label">Sentinel / Operations</div><h1 className="mt-2 text-[22px] font-semibold tracking-[-0.025em]">Operations overview</h1><p className="mt-1 text-[12px] text-[var(--text-secondary)]">Prioritized behavioral threats from the verified SentinelAI baseline.</p></div>
        <div className="grid grid-cols-2 sm:grid-cols-4 xl:min-w-[540px]">
          <CompactStat risk="Critical" value={overview.activeThreats.Critical} label="Critical" />
          <CompactStat risk="High" value={overview.activeThreats.High} label="High" />
          <CompactStat risk="Medium" value={overview.activeThreats.Medium} label="Medium" />
          <CompactStat value={system.model.status.toUpperCase()} label={system.model.label} />
        </div>
      </section>

      <section aria-labelledby="priority-queue">
        <div className="mb-3"><SectionHeading eyebrow="Triage" title="Priority threat queue" id="priority-queue" description="Highest persisted risk scores requiring analyst review" action={<Link href="/threats" className="flex items-center gap-1 rounded-sm text-[11px] font-medium text-[var(--accent-strong)] hover:text-foreground">View all {counts.alerts} <ChevronRight aria-hidden="true" className="size-3" /></Link>} /></div>
        <ThreatQueue threats={threats} compact />
      </section>

      <section aria-labelledby="analytics" className="space-y-3">
        <SectionHeading eyebrow="Baseline telemetry" title="Behavioral activity" id="analytics" description={`Daily persisted detection activity${firstDay && lastDay ? ` · ${firstDay} to ${lastDay}` : ""}`} />
        <div className="grid gap-4 xl:grid-cols-2">
          <article className="panel p-4"><div className="mb-2"><h3 className="text-[12px] font-semibold">Risk activity</h3><p className="mt-0.5 text-[10px] text-[var(--text-muted)]">Daily mean risk with generated alert volume</p></div><RiskActivityChart points={overview.riskActivity} /></article>
          <article className="panel p-4"><div className="mb-2"><h3 className="text-[12px] font-semibold">Anomaly activity</h3><p className="mt-0.5 text-[10px] text-[var(--text-muted)]">Persisted anomaly percentile distribution</p></div><AnomalyActivityChart points={overview.anomalyActivity} /></article>
        </div>
      </section>
    </div>
  );
}
