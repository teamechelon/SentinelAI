import { Search } from "lucide-react";
import Link from "next/link";

export function ActivityFilterBar({ values }: { values: Record<string, string> }) {
  return (
    <form action="/activity" className="panel grid gap-3 p-3 sm:grid-cols-2 xl:grid-cols-[minmax(220px,1fr)_repeat(5,minmax(120px,0.55fr))_auto]">
      <label className="relative sm:col-span-2 xl:col-span-1">
        <span className="sr-only">Search activity</span>
        <Search aria-hidden="true" className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-[var(--text-muted)]" />
        <input name="q" defaultValue={values.q} placeholder="Event, employee, device, location" className="control w-full pl-9 pr-3" />
      </label>
      <label><span className="sr-only">Department</span><input name="department" defaultValue={values.department} placeholder="Department" className="control w-full px-3" /></label>
      <label><span className="sr-only">Activity type</span><input name="activityType" defaultValue={values.activityType} placeholder="Activity type" className="control w-full px-3" /></label>
      <label><span className="sr-only">Scenario</span><input name="scenario" defaultValue={values.scenario} placeholder="Scenario" className="control w-full px-3" /></label>
      <label>
        <span className="sr-only">Risk level</span>
        <select name="riskLevel" defaultValue={values.riskLevel || "All"} className="control w-full px-3">
          <option>All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option>
        </select>
      </label>
      <label>
        <span className="sr-only">Sort activity</span>
        <select name="sort" defaultValue={values.sort || "timestamp"} className="control w-full px-3">
          <option value="timestamp">Newest activity</option><option value="risk_score">Risk score</option><option value="employee">Employee</option><option value="activity_type">Activity type</option>
        </select>
      </label>
      <div className="flex items-center gap-2">
        <button type="submit" className="control border-[var(--accent-dim)] bg-[var(--accent-dim)] px-4 font-semibold text-[var(--accent-strong)] hover:border-[var(--accent)]">Apply</button>
        <Link href="/activity" className="rounded-sm px-2 py-2 text-[11px] text-[var(--text-muted)] hover:text-foreground">Reset</Link>
      </div>
      <label className="flex min-h-8 items-center gap-2 text-[11px] text-[var(--text-secondary)] sm:col-span-2 xl:col-span-full">
        <input type="checkbox" name="anomalousOnly" value="true" defaultChecked={values.anomalousOnly === "true"} className="size-3.5 accent-[var(--accent)]" />
        Persisted anomaly percentile at or above 95
      </label>
    </form>
  );
}
