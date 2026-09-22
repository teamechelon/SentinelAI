import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { ActivityTable } from "@/components/activity/activity-table";
import { ThreatStoryPanel } from "@/components/threat-intelligence/threat-story-panel";
import { getSentinelDataSource } from "@/data/data-source";

type Params = Promise<{ id: string }>;
export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> { return { title: `Activity ${(await params).id}` }; }
export default async function ActivityDetailPage({ params }: { params: Params }) {
  const { id } = await params;
  const source = getSentinelDataSource();
  const [activity, report] = await Promise.all([source.listActivity({ q: id, pageSize: 10 }), source.getMitreEvent(id)]);
  const event = activity.items.find((item) => item.eventId === id);
  if (!event || !report) notFound();
  return <div className="mx-auto max-w-[1500px] space-y-6"><Link href="/activity" className="inline-flex items-center gap-1.5 text-[11px] text-[var(--text-muted)] hover:text-foreground"><ArrowLeft className="size-3" aria-hidden="true" />Activity Monitor</Link><section className="border-b border-border pb-5"><div className="tech-label">Event detail / {event.eventId}</div><h1 className="mt-2 text-[22px] font-semibold tracking-[-0.025em]">{event.activityType.replaceAll("_", " ")}</h1><p className="mt-1 text-[12px] text-[var(--text-secondary)]">{event.employeeName} · {event.employeeId} · {event.city}, {event.country}</p></section><ActivityTable items={[event]} /><ThreatStoryPanel report={report} /></div>;
}
