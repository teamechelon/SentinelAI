import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { ActivityTable } from "@/components/activity/activity-table";
import { SectionHeading } from "@/components/system/section-heading";
import { ThreatQueue } from "@/components/threats/threat-queue";
import { getSentinelDataSource } from "@/data/data-source";

type Params = Promise<{ id: string }>;
export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> { return { title: `User ${(await params).id}` }; }
function hour(value: number | null) { if (value === null) return "Unavailable"; const whole = Math.floor(value) % 24; const minute = Math.round((value - Math.floor(value)) * 60); return `${String(whole).padStart(2, "0")}:${String(minute).padStart(2, "0")}`; }

export default async function UserDetailPage({ params }: { params: Params }) {
  const { id } = await params;
  const user = await getSentinelDataSource().getUser(id);
  if (!user) notFound();
  const baseline = user.personalBaseline;
  const peer = user.peerBaseline;
  return <div className="mx-auto max-w-[1600px] space-y-6">
    <Link href="/users" className="inline-flex items-center gap-1.5 text-[11px] text-[var(--text-muted)] hover:text-foreground"><ArrowLeft aria-hidden="true" className="size-3" />All users</Link>
    <section className="border-b border-border pb-5"><div className="tech-label">Sentinel / Identities / {user.employeeId}</div><h1 className="mt-2 text-[22px] font-semibold tracking-[-0.025em]">{user.employeeName}</h1><p className="mt-1 text-[12px] text-[var(--text-secondary)]">{user.department} · {user.role} · {user.homeCity}, {user.homeCountry}</p></section>
    <section aria-labelledby="baselines" className="space-y-3"><SectionHeading id="baselines" eyebrow="Behavior context" title="Personal and peer baselines" description="Descriptive historical context; these values do not replace persisted detection scores." />
      <div className="grid gap-4 xl:grid-cols-2">
        <article className="panel p-4"><h3 className="text-[12px] font-semibold">Personal baseline</h3><dl className="mt-4 grid grid-cols-2 gap-x-5 gap-y-4 text-[11px]"><div><dt className="tech-label">Login window</dt><dd className="mt-1 font-mono">{hour(baseline.normalLoginStart)}–{hour(baseline.normalLoginEnd)}</dd></div><div><dt className="tech-label">Confidence</dt><dd className="mt-1 font-mono">{Math.round(baseline.confidence * 100)}% · {baseline.historyEventCount} events</dd></div><div><dt className="tech-label">Usual locations</dt><dd className="mt-1">{baseline.usualCities.join(", ") || "Unavailable"}</dd></div><div><dt className="tech-label">Typical sensitivity</dt><dd className="mt-1">{baseline.typicalFileSensitivity.join(", ") || "Unavailable"}</dd></div><div><dt className="tech-label">Mean downloads</dt><dd className="mt-1 font-mono">{baseline.averageDownloadCount.toFixed(1)} files · {baseline.averageDownloadSizeMb.toFixed(1)} MB</dd></div><div><dt className="tech-label">Known devices</dt><dd className="mt-1 font-mono">{baseline.knownDevices.length}</dd></div></dl></article>
        <article className="panel p-4"><h3 className="text-[12px] font-semibold">Peer baseline</h3>{peer ? <dl className="mt-4 grid grid-cols-2 gap-x-5 gap-y-4 text-[11px]"><div><dt className="tech-label">Peer group</dt><dd className="mt-1">{peer.peerGroup.department} · {peer.peerGroup.role}</dd></div><div><dt className="tech-label">Status</dt><dd className="mt-1 font-mono">{peer.status} · {Math.round(peer.confidence * 100)}%</dd></div><div><dt className="tech-label">Members</dt><dd className="mt-1 font-mono">{peer.contributingMemberCount} contributing / {peer.memberCount}</dd></div><div><dt className="tech-label">Login window</dt><dd className="mt-1 font-mono">{hour(peer.normalLoginStart)}–{hour(peer.normalLoginEnd)}</dd></div><div><dt className="tech-label">Usual locations</dt><dd className="mt-1">{peer.usualCities.join(", ") || "Unavailable"}</dd></div><div><dt className="tech-label">Historical events</dt><dd className="mt-1 font-mono">{peer.historyEventCount}</dd></div></dl> : <p className="mt-4 text-[11px] text-[var(--text-muted)]">Peer context is available in live API mode. The offline fixture intentionally contains no fabricated peer assessment.</p>}</article>
      </div>
    </section>
    {user.currentAssessment && <section className="panel p-4"><SectionHeading eyebrow="Latest event" title="Behavioral comparison" description={`${user.currentAssessment.comparisonCase.replaceAll("_", " ")} · personal ${user.currentAssessment.personalStatus} · peer ${user.currentAssessment.peerStatus}`} /><div className="mt-4 grid gap-3 sm:grid-cols-2"><div><span className="tech-label">Personal deviation</span><div className="mt-1 font-mono text-[16px]">{user.currentAssessment.personalDeviation?.toFixed(3) ?? "Unavailable"}</div></div><div><span className="tech-label">Peer deviation</span><div className="mt-1 font-mono text-[16px]">{user.currentAssessment.peerDeviation?.toFixed(3) ?? "Unavailable"}</div></div></div></section>}
    <section className="space-y-3"><SectionHeading eyebrow="Telemetry" title="Recent activity" description={`${user.activityHistory.length} most recent persisted events`} /><ActivityTable items={user.activityHistory} /></section>
    <section className="space-y-3"><SectionHeading eyebrow="Triage" title="Related alerts" description="Persisted alert records for this user" />{user.relatedAlerts.length ? <ThreatQueue threats={user.relatedAlerts} compact /> : <div className="panel p-5 text-[11px] text-[var(--text-muted)]">No persisted alerts for this user.</div>}</section>
  </div>;
}
