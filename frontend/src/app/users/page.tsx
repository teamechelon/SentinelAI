import type { Metadata } from "next";
import Link from "next/link";
import { Search } from "lucide-react";
import { UserTable } from "@/components/users/user-table";
import { getSentinelDataSource } from "@/data/data-source";

export const metadata: Metadata = { title: "Users" };
type SearchParams = Promise<Record<string, string | string[] | undefined>>;
function scalar(value: string | string[] | undefined) { return Array.isArray(value) ? value[0] : value; }

export default async function UsersPage({ searchParams }: { searchParams: SearchParams }) {
  const params = await searchParams;
  const q = scalar(params.q) ?? ""; const department = scalar(params.department) ?? ""; const role = scalar(params.role) ?? "";
  const sort = (scalar(params.sort) ?? "name") as "name" | "department" | "risk" | "activity";
  const result = await getSentinelDataSource().listUsers({ q, department, role, sort, direction: sort === "risk" || sort === "activity" ? "desc" : "asc", pageSize: 100 });
  return <div className="mx-auto max-w-[1600px] space-y-5">
    <section className="flex flex-col gap-3 border-b border-border pb-5 sm:flex-row sm:items-end sm:justify-between"><div><div className="tech-label">Sentinel / Identities</div><h1 className="mt-2 text-[24px] font-bold tracking-[-0.03em]">User Behaviour</h1><p className="mt-1 text-[12px] text-[var(--text-secondary)]">Personal baselines, peer context, activity, and persisted alerts.</p></div><div aria-live="polite" className="font-mono text-[11px] text-[var(--text-muted)]"><span className="text-foreground">{result.page.total}</span> monitored users</div></section>
    <form action="/users" className="panel grid gap-3 p-3 sm:grid-cols-2 xl:grid-cols-[minmax(220px,1fr)_repeat(3,minmax(150px,0.5fr))_auto]">
      <label className="relative sm:col-span-2 xl:col-span-1"><span className="sr-only">Search users</span><Search aria-hidden="true" className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-[var(--text-muted)]" /><input name="q" defaultValue={q} placeholder="Name or employee ID" className="control w-full pl-9 pr-3" /></label>
      <label><span className="sr-only">Department</span><input name="department" defaultValue={department} placeholder="Department" className="control w-full px-3" /></label>
      <label><span className="sr-only">Role</span><input name="role" defaultValue={role} placeholder="Role" className="control w-full px-3" /></label>
      <label><span className="sr-only">Sort users</span><select name="sort" defaultValue={sort} className="control w-full px-3"><option value="name">Name</option><option value="department">Department</option><option value="risk">Latest risk</option><option value="activity">Activity count</option></select></label>
      <div className="flex items-center gap-2"><button className="control border-[var(--accent-dim)] bg-[var(--accent-dim)] px-4 font-semibold text-[var(--accent-strong)] hover:border-[var(--accent)]">Apply</button><Link href="/users" className="rounded-sm px-2 py-2 text-[11px] text-[var(--text-muted)] hover:text-foreground">Reset</Link></div>
    </form>
    <UserTable items={result.items} />
  </div>;
}
