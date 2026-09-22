import type { Metadata } from "next";
import Link from "next/link";
import { Crosshair, GitBranch, Layers3, ShieldCheck } from "lucide-react";
import { ThreatStoryPanel } from "@/components/threat-intelligence/threat-story-panel";
import { getSentinelDataSource } from "@/data/data-source";

export const metadata: Metadata = { title: "Threat Intelligence" };
type SearchParams = Promise<Record<string, string | string[] | undefined>>;
function scalar(value: string | string[] | undefined) { return Array.isArray(value) ? value[0] : value; }

export default async function ThreatIntelligencePage({ searchParams }: { searchParams: SearchParams }) {
  const params = await searchParams;
  const source = getSentinelDataSource();
  const [overview, catalog] = await Promise.all([source.getMitreOverview(), source.getMitreCatalog()]);
  const eventId = scalar(params.event);
  const runId = scalar(params.run);
  const alertId = scalar(params.alert);
  const techniqueId = scalar(params.technique);
  const requestedReport = eventId ? await source.getMitreEvent(eventId) : runId ? await source.getMitreAttackRun(runId) : alertId ? await source.getMitreAlert(alertId) : null;
  const report = requestedReport ?? overview.recentReports[0] ?? null;
  const selectedTechnique = catalog.techniques.find((item) => item.techniqueId === techniqueId) ?? catalog.techniques.find((item) => item.techniqueId === report?.mappings[0]?.techniqueId) ?? catalog.techniques[0];
  const metrics = [
    { label: "Supported techniques", value: overview.catalogTechniqueCount, icon: Layers3 },
    { label: "Observed coverage", value: overview.mappedTechniqueCount, icon: Crosshair },
    { label: "Recent stories", value: overview.storyCount, icon: ShieldCheck },
    { label: "Correlated cases", value: overview.correlatedCaseCount, icon: GitBranch },
  ];
  return <div className="mx-auto max-w-[1600px] space-y-6">
    <section className="flex flex-col gap-4 border-b border-border pb-5 lg:flex-row lg:items-end lg:justify-between"><div><div className="tech-label">Sentinel / Threat intelligence</div><h1 className="mt-2 text-[24px] font-bold tracking-[-0.03em]">MITRE ATT&amp;CK Intelligence</h1><p className="mt-1 max-w-3xl text-[12px] text-[var(--text-secondary)]">Evidence-backed technique mappings and ordered threat stories derived from persisted SentinelAI telemetry.</p></div><div className="text-right"><a href={overview.sourceUrl} target="_blank" rel="noreferrer" className="font-mono text-[10px] text-[var(--accent-strong)] hover:text-foreground">{overview.sourceVersion}</a><p className="mt-1 font-mono text-[9px] text-[var(--text-muted)]">Local catalog · production risk contribution {overview.affectsProductionRisk ? "enabled" : "disabled"}</p></div></section>

    <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">{metrics.map(({ label, value, icon: Icon }) => <article key={label} className="panel p-4"><div className="flex items-center justify-between"><span className="tech-label">{label}</span><Icon className="size-4 text-[var(--accent)]" aria-hidden="true" /></div><div className="mt-3 font-mono text-[24px] font-semibold">{value}</div></article>)}</section>

    <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
      <div className="space-y-5">{report ? <ThreatStoryPanel report={report} /> : <div className="panel p-8 text-center text-[11px] text-[var(--text-muted)]">No evidence-backed threat story is available yet. Complete an Attack Lab run to generate one.</div>}</div>
      <aside className="space-y-5">
        <section className="panel p-4"><h2 className="tech-label">Technique coverage</h2><div className="mt-3 space-y-2">{catalog.techniques.map((item) => <Link key={item.techniqueId} href={`/threat-intelligence?technique=${item.techniqueId}`} className={`flex items-center justify-between rounded-md border px-3 py-2.5 text-[10px] transition-colors ${selectedTechnique?.techniqueId === item.techniqueId ? "border-[var(--accent-dim)] bg-[var(--surface-selected)]" : "border-border hover:bg-[var(--surface-hover)]"}`}><span><span className="font-mono text-[var(--accent-strong)]">{item.techniqueId}</span><span className="ml-2 font-medium">{item.name}</span></span><span className="font-mono text-[var(--text-muted)]">{overview.techniqueCounts[item.techniqueId] ?? 0}</span></Link>)}</div></section>
        {selectedTechnique && <section className="panel p-4"><div className="tech-label">Technique detail</div><div className="mt-3 font-mono text-[11px] font-semibold text-[var(--accent-strong)]">{selectedTechnique.techniqueId}</div><h2 className="mt-1 text-[15px] font-semibold">{selectedTechnique.name}</h2><p className="mt-3 text-[10px] leading-5 text-[var(--text-secondary)]">{selectedTechnique.description}</p><div className="mt-3 flex flex-wrap gap-1.5">{selectedTechnique.tactics.map((tactic) => <span key={tactic} className="rounded-sm border border-border bg-[var(--surface-elevated)] px-2 py-1 text-[9px]">{tactic}</span>)}</div><a href={selectedTechnique.sourceUrl} target="_blank" rel="noreferrer" className="mt-4 inline-block text-[9px] text-[var(--accent-strong)] hover:text-foreground">View official MITRE entry ↗</a></section>}
        <section className="panel p-4"><h2 className="tech-label">Recent stories</h2><div className="mt-3 space-y-3">{overview.recentReports.map((item) => <Link key={`${item.subjectType}-${item.subjectId}`} href={`/threat-intelligence?${item.subjectType === "alert" ? "alert" : item.subjectType === "attack_run" ? "run" : "event"}=${encodeURIComponent(item.subjectId)}`} className="block border-b border-border pb-3 last:border-0"><span className="block truncate text-[10px] font-medium">{item.threatStory.title}</span><span className="mt-1 block font-mono text-[8px] text-[var(--text-muted)]">{item.subjectId} · {item.mappings.length} mappings</span></Link>)}</div></section>
      </aside>
    </section>
  </div>;
}
