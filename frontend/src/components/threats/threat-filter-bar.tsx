import Link from "next/link";
import type { AlertStatus, RiskLevel } from "@/domain/sentinel";
import { riskFilters, statusFilters } from "@/data/threat-query";

export function ThreatFilterBar({ q, risk, status }: { q: string; risk: RiskLevel | "All"; status: AlertStatus | "All" }) {
  const active = Boolean(q || risk !== "All" || status !== "All");
  return (
    <form className="panel flex flex-col gap-3 p-3 md:flex-row md:items-end" action="/threats" role="search" aria-label="Filter threat queue">
      <label className="min-w-0 flex-1"><span className="mb-1.5 block tech-label">Search</span><input name="q" defaultValue={q} placeholder="Alert ID, employee, title, or scenario" className="control w-full px-3 placeholder:text-[var(--text-muted)]" /></label>
      <label className="md:w-36"><span className="mb-1.5 block tech-label">Severity</span><select name="risk" defaultValue={risk} className="control w-full px-3">{riskFilters.map((value) => <option key={value}>{value}</option>)}</select></label>
      <label className="md:w-40"><span className="mb-1.5 block tech-label">Status</span><select name="status" defaultValue={status} className="control w-full px-3">{statusFilters.map((value) => <option key={value}>{value}</option>)}</select></label>
      <button type="submit" className="control border-[var(--accent)] bg-[var(--accent)] px-4 font-semibold text-[#06100f] hover:border-[var(--accent-strong)] hover:bg-[var(--accent-strong)]">Apply filters</button>
      {active && <Link href="/threats" className="flex h-9 items-center justify-center rounded-sm px-2 text-[11px] text-[var(--text-muted)] hover:text-foreground">Reset</Link>}
    </form>
  );
}
