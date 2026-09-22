import type { Metadata } from "next";
import Link from "next/link";
import { ActivityFilterBar } from "@/components/activity/activity-filter-bar";
import { ActivityTable } from "@/components/activity/activity-table";
import { getSentinelDataSource } from "@/data/data-source";
import type { RiskLevel } from "@/domain/sentinel";

export const metadata: Metadata = { title: "Activity" };
type SearchParams = Promise<Record<string, string | string[] | undefined>>;
function scalar(value: string | string[] | undefined) { return Array.isArray(value) ? value[0] : value; }
function positive(value: string | undefined, fallback: number) { const parsed = Number(value); return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback; }

export default async function ActivityPage({ searchParams }: { searchParams: SearchParams }) {
  const params = await searchParams;
  const values = Object.fromEntries(Object.entries(params).map(([key, value]) => [key, scalar(value) ?? ""]));
  const page = positive(values.page, 1);
  const result = await getSentinelDataSource().listActivity({
    q: values.q, start: values.start, end: values.end, department: values.department, activityType: values.activityType, scenario: values.scenario,
    riskLevel: values.riskLevel as RiskLevel | "All" | undefined, anomalousOnly: values.anomalousOnly === "true",
    sort: (values.sort || "timestamp") as "timestamp" | "risk_score" | "employee" | "activity_type",
    direction: "desc", page, pageSize: 50,
  });
  const href = (target: number) => { const query = new URLSearchParams(Object.entries(values).filter(([, value]) => value && value !== "All")); query.set("page", String(target)); return `/activity?${query}`; };
  return <div className="mx-auto max-w-[1700px] space-y-5">
    <section className="flex flex-col gap-3 border-b border-border pb-5 sm:flex-row sm:items-end sm:justify-between"><div><div className="tech-label">Sentinel / Telemetry</div><h1 className="mt-2 text-[24px] font-bold tracking-[-0.03em]">Activity Monitor</h1><p className="mt-1 text-[12px] text-[var(--text-secondary)]">Search and filter the complete persisted security event dataset.</p></div><div aria-live="polite" className="font-mono text-[11px] text-[var(--text-muted)]"><span className="text-foreground">{result.page.total}</span> events · page {result.page.page} / {result.page.totalPages}</div></section>
    <ActivityFilterBar values={values} />
    <ActivityTable items={result.items} />
    <nav aria-label="Activity pagination" className="flex items-center justify-between"><Link aria-disabled={page <= 1} tabIndex={page <= 1 ? -1 : undefined} href={page <= 1 ? href(1) : href(page - 1)} className={`control grid place-items-center px-4 ${page <= 1 ? "pointer-events-none opacity-40" : ""}`}>Previous</Link><span className="font-mono text-[10px] text-[var(--text-muted)]">Showing {result.items.length} of {result.page.total}</span><Link aria-disabled={page >= result.page.totalPages} tabIndex={page >= result.page.totalPages ? -1 : undefined} href={page >= result.page.totalPages ? href(page) : href(page + 1)} className={`control grid place-items-center px-4 ${page >= result.page.totalPages ? "pointer-events-none opacity-40" : ""}`}>Next</Link></nav>
  </div>;
}
