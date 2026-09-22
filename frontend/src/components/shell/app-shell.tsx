import Link from "next/link";
import { Database, Search, ShieldCheck } from "lucide-react";
import type { SystemStatusSnapshot } from "@/domain/sentinel";
import { SystemStatus } from "@/components/system/system-status";
import { SidebarNav } from "./sidebar-nav";

export function AppShell({ children, system }: { children: React.ReactNode; system: SystemStatusSnapshot }) {
  return (
    <div className="min-h-screen bg-background lg:grid lg:grid-cols-[208px_minmax(0,1fr)]">
      <a href="#main-content" className="fixed left-3 top-3 z-50 -translate-y-20 rounded bg-[var(--accent)] px-3 py-2 text-[12px] font-semibold text-[#06100f] transition-transform focus:translate-y-0">Skip to main content</a>
      <aside className="hidden border-r border-border bg-[var(--surface)] lg:fixed lg:inset-y-0 lg:flex lg:w-[208px] lg:flex-col">
        <Link href="/" className="flex h-[52px] items-center gap-3 border-b border-border px-4">
          <span className="grid size-8 place-items-center rounded-md border border-[var(--accent-dim)] bg-[var(--accent-dim)] text-[var(--accent)]"><ShieldCheck className="size-4" /></span>
          <span><span className="block text-[14px] font-semibold tracking-tight">SentinelAI</span><span className="tech-label">Operations</span></span>
        </Link>
        <div className="flex-1 py-4"><SidebarNav /></div>
        <div className="border-t border-border px-5 py-4">
          <div className="mb-2 flex items-center gap-2 tech-label"><Database className="size-3" /> System</div>
          <SystemStatus system={system} />
        </div>
      </aside>

      <div className="min-w-0 lg:col-start-2">
        <header className="sticky top-0 z-30 border-b border-border bg-[color:var(--background)]/95 backdrop-blur">
          <div className="flex h-[52px] items-center gap-3 px-4 md:px-6">
            <Link href="/" className="font-semibold lg:hidden">SentinelAI</Link>
            <form action="/threats" className="relative ml-auto w-full max-w-sm">
              <Search aria-hidden="true" className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-[var(--text-muted)]" />
              <input name="q" aria-label="Search threats" placeholder="Search alerts or employees" className="control w-full bg-[var(--surface)] pl-9 pr-3 placeholder:text-[var(--text-muted)]" />
            </form>
            <div className="hidden items-center gap-2 border-l border-border pl-4 sm:flex">
              <span aria-hidden="true" className="size-1.5 rounded-full bg-[var(--text-muted)]" /><span className="font-mono text-[10px] font-semibold tracking-wider text-[var(--text-secondary)]">{system.data.label}</span>
            </div>
            <div className="hidden min-w-28 border-l border-border pl-4 xl:block">
              <span className="block text-[11px] font-medium">{system.operator.label}</span><span className="tech-label">{system.operator.session} session</span>
            </div>
          </div>
          <div className="border-t border-border lg:hidden"><SidebarNav compact /></div>
        </header>
        <main id="main-content" tabIndex={-1} className="px-4 py-5 md:px-6 md:py-6 xl:px-8">{children}</main>
      </div>
    </div>
  );
}
