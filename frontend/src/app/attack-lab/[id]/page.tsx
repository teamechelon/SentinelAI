import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { ActivityTable } from "@/components/activity/activity-table";
import { SectionHeading } from "@/components/system/section-heading";
import { ThreatSeverity } from "@/components/threats/threat-severity";
import { getSentinelDataSource } from "@/data/data-source";
import { ThreatStoryPanel } from "@/components/threat-intelligence/threat-story-panel";

type Params = Promise<{ id: string }>;
export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> { return { title: `Attack Lab ${(await params).id}` }; }
export default async function AttackLabRunPage({ params }: { params: Params }) {
  const { id } = await params; const source = getSentinelDataSource(); const [run, mitre] = await Promise.all([source.getAttackLabRun(id), source.getMitreAttackRun(id)]); if (!run) notFound();
  return <div className="mx-auto max-w-[1500px] space-y-6"><Link href="/attack-lab" className="inline-flex items-center gap-1.5 text-[11px] text-[var(--text-muted)] hover:text-foreground"><ArrowLeft aria-hidden="true" className="size-3" />Attack Lab</Link>
    <section className="flex flex-col gap-3 border-b border-border pb-5 sm:flex-row sm:items-end sm:justify-between"><div><div className="tech-label">Simulation / {run.simulationId}</div><h1 className="mt-2 text-[22px] font-semibold tracking-[-0.025em]">{run.scenario.replaceAll("_", " ")}</h1><p className="mt-1 text-[12px] text-[var(--text-secondary)]">{run.employeeId} · {run.intensity} · {new Date(run.startTime).toLocaleString("en-GB", { timeZone: "UTC" })} UTC</p></div><span className="w-fit rounded-sm border border-[var(--accent-dim)] px-2 py-1 font-mono text-[10px] uppercase text-[var(--accent-strong)]">{run.status}</span></section>
    <section className="space-y-3"><SectionHeading eyebrow="Ordered evidence" title="Sequence findings" description="Deterministic matches over this run; no confidence probability is asserted." />{run.findings.length ? <div className="grid gap-3 lg:grid-cols-2">{run.findings.map((finding) => <article key={finding.code} className="panel p-4"><div className="flex items-start justify-between gap-3"><div><code className="font-mono text-[9px] text-[var(--text-muted)]">{finding.code}</code><h3 className="mt-1 text-[12px] font-semibold">{finding.title}</h3></div><ThreatSeverity level={finding.severity} /></div><ol className="mt-4 space-y-2">{finding.evidence.map((evidence, index) => <li key={evidence} className="flex gap-3 text-[10px] text-[var(--text-secondary)]"><span className="font-mono text-[var(--accent-strong)]">{String(index + 1).padStart(2, "0")}</span><span>{evidence}<code className="ml-2 text-[var(--text-muted)]">{finding.eventIds[index]}</code></span></li>)}</ol><p className="mt-4 border-t border-border pt-3 font-mono text-[9px] text-[var(--text-muted)]">Observed within configured {finding.windowMinutes}-minute window</p></article>)}</div> : <div className="panel p-5 text-[11px] text-[var(--text-muted)]">No configured sequence rule matched this run.</div>}</section>
    {(() => {
      const devices = Array.from(new Set(run.events.map(e => e.deviceId).filter(Boolean)));
      const ips = Array.from(new Set(run.events.map(e => e.ipAddress).filter(Boolean)));
      const locations = Array.from(new Set(run.events.map(e => e.city && e.country ? `${e.city}, ${e.country}` : "").filter(Boolean)));
      return (
        <section className="space-y-3">
          <SectionHeading eyebrow="Graph context" title="Attack Run Entities" description="Derived from the events in this simulation run" />
          <div className="panel p-4 text-[11px]">
            <dl className="grid grid-cols-1 md:grid-cols-3 gap-x-5 gap-y-4">
              <div><dt className="tech-label">Unique Devices</dt><dd className="mt-1 font-mono break-all">{devices.length > 0 ? devices.join(", ") : "None"}</dd></div>
              <div><dt className="tech-label">Unique IPs</dt><dd className="mt-1 font-mono break-all">{ips.length > 0 ? ips.join(", ") : "None"}</dd></div>
              <div><dt className="tech-label">Locations Involved</dt><dd className="mt-1 break-all">{locations.length > 0 ? locations.join(" · ") : "None"}</dd></div>
            </dl>
          </div>
        </section>
      );
    })()}
    {mitre && <ThreatStoryPanel report={mitre} />}
    <section className="space-y-3"><SectionHeading eyebrow="Persisted telemetry" title="Run events" description={`${run.events.length} events processed by the existing SentinelAI detection path`} /><ActivityTable items={run.events} /></section>
  </div>;
}
