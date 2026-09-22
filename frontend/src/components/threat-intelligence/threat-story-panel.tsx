import Link from "next/link";
import { ExternalLink } from "lucide-react";
import type { MitreReport } from "@/domain/sentinel";
import { ThreatSeverity } from "@/components/threats/threat-severity";

function stamp(value: string) {
  return new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(new Date(value));
}

export function ThreatStoryPanel({ report, compact = false }: { report: MitreReport; compact?: boolean }) {
  const story = report.threatStory;
  return (
    <section className="panel overflow-hidden" aria-labelledby={`story-${report.subjectId}`}>
      <div className="border-b border-border bg-[var(--surface-elevated)] px-5 py-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <div className="tech-label">Threat story / {report.subjectType.replace("_", " ")} / {report.subjectId}</div>
            <h2 id={`story-${report.subjectId}`} className="mt-2 text-[16px] font-semibold tracking-[-0.02em]">{story.title}</h2>
            <p className="mt-1 max-w-4xl text-[11px] leading-5 text-[var(--text-secondary)]">{story.summary}</p>
          </div>
          <div className="flex items-center gap-2"><ThreatSeverity level={story.riskLevel} /><span className="rounded-sm border border-border px-2 py-1 font-mono text-[9px] uppercase text-[var(--text-secondary)]">{report.confidence} confidence</span></div>
        </div>
      </div>

      <div className="grid gap-0 divide-y divide-border lg:grid-cols-[1.1fr_0.9fr] lg:divide-x lg:divide-y-0">
        <div className="p-5">
          <h3 className="tech-label">Ordered timeline</h3>
          <ol className="mt-4 space-y-4">
            {report.timeline.map((entry, index) => (
              <li key={`${entry.eventId}-${index}`} className="grid grid-cols-[24px_1fr] gap-3">
                <span className="flex size-6 items-center justify-center rounded-full border border-[var(--accent-dim)] font-mono text-[9px] text-[var(--accent-strong)]">{index + 1}</span>
                <div className="border-b border-border pb-4 last:border-0">
                  <div className="flex flex-wrap items-baseline justify-between gap-2"><span className="text-[11px] font-semibold">{entry.activity}</span><time className="font-mono text-[9px] text-[var(--text-muted)]">{stamp(entry.timestamp)} UTC</time></div>
                  <p className="mt-1 text-[10px] leading-4 text-[var(--text-secondary)]">{entry.observation}</p>
                  <Link href={`/activity/${encodeURIComponent(entry.eventId)}`} className="mt-1 inline-block font-mono text-[9px] text-[var(--accent-strong)] hover:text-foreground">{entry.eventId}</Link>
                </div>
              </li>
            ))}
          </ol>
        </div>

        <div className="p-5">
          <h3 className="tech-label">MITRE ATT&amp;CK mappings</h3>
          {report.mappings.length ? <div className="mt-4 space-y-3">{report.mappings.map((mapping) => (
            <article key={mapping.techniqueId} className="rounded-md border border-border bg-background p-4">
              <div className="flex items-start justify-between gap-3"><div><span className="font-mono text-[10px] font-semibold text-[var(--accent-strong)]">{mapping.techniqueId}</span><h4 className="mt-1 text-[12px] font-semibold">{mapping.techniqueName}</h4></div><span className="rounded-sm bg-[var(--surface-selected)] px-2 py-1 font-mono text-[8px] uppercase text-[var(--text-secondary)]">{mapping.confidence}</span></div>
              <p className="mt-2 text-[10px] leading-4 text-[var(--text-secondary)]">{mapping.explanation}</p>
              <dl className="mt-3 grid gap-2 text-[9px] sm:grid-cols-2"><div><dt className="text-[var(--text-muted)]">Tactic</dt><dd className="mt-0.5 font-medium">{mapping.tactic}</dd></div><div><dt className="text-[var(--text-muted)]">Evidence</dt><dd className="mt-0.5 font-mono">{mapping.evidenceCount} items</dd></div></dl>
              <Link href={`/threat-intelligence?technique=${mapping.techniqueId}`} className="mt-3 inline-flex items-center gap-1 text-[9px] text-[var(--accent-strong)] hover:text-foreground">Technique detail <ExternalLink className="size-2.5" aria-hidden="true" /></Link>
            </article>
          ))}</div> : <p className="mt-4 rounded-md border border-border bg-background p-4 text-[10px] leading-4 text-[var(--text-muted)]">No ATT&amp;CK technique is asserted because this evidence does not meet the mapper’s direct rule or sequence criteria.</p>}
        </div>
      </div>

      {!compact && <div className="grid gap-5 border-t border-border p-5 md:grid-cols-3">
        <div><h3 className="tech-label">Key evidence</h3><ul className="mt-3 space-y-2 text-[10px] text-[var(--text-secondary)]">{story.keyEvidence.map((item) => <li key={item}>• {item}</li>)}{!story.keyEvidence.length && <li>No qualifying evidence.</li>}</ul></div>
        <div><h3 className="tech-label">Correlation context</h3><ul className="mt-3 space-y-2 text-[10px] text-[var(--text-secondary)]">{story.sequenceContext.map((item) => <li key={item}>• {item}</li>)}{story.graphContext.map((item) => <li key={item}>• {item}</li>)}{!story.sequenceContext.length && !story.graphContext.length && <li>Single-event context only.</li>}</ul></div>
        <div><h3 className="tech-label">Investigation focus</h3><ul className="mt-3 space-y-2 text-[10px] text-[var(--text-secondary)]">{story.investigationFocus.map((item) => <li key={item}>• {item}</li>)}</ul></div>
      </div>}
    </section>
  );
}
