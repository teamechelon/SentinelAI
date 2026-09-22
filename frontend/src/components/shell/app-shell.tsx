import Link from "next/link";
import { Bell, Search, ShieldCheck } from "lucide-react";
import type { SystemStatusSnapshot } from "@/domain/sentinel";
import { SystemStatus } from "@/components/system/system-status";
import { SidebarNav } from "./sidebar-nav";

export function AppShell({ children, system }: { children: React.ReactNode; system: SystemStatusSnapshot }) {
  return (
    <div className="min-h-screen bg-background lg:grid lg:grid-cols-[248px_minmax(0,1fr)]">
      <a href="#main-content" className="fixed left-3 top-3 z-50 -translate-y-20 rounded-lg bg-[var(--accent)] px-3 py-2 text-[12px] font-semibold text-white transition-transform focus:translate-y-0">Skip to main content</a>
      <aside className="hidden border-r border-border bg-[var(--surface)] lg:fixed lg:inset-y-0 lg:flex lg:w-[248px] lg:flex-col">
        <Link href="/" className="flex min-h-[84px] items-center gap-3 border-b border-border px-5">
          <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-[var(--accent)] text-white shadow-sm"><ShieldCheck className="size-5" /></span>
          <span><span className="block text-[16px] font-bold tracking-[-0.02em]">SentinelAI</span><span className="mt-0.5 block max-w-[150px] text-[9px] font-medium leading-3.5 text-[var(--text-muted)]">Explainable Behaviour &amp; Threat Intelligence</span></span>
        </Link>
        <div className="flex-1 py-6"><SidebarNav /></div>
        <div className="m-4 rounded-xl border border-[#dfe8f7] bg-[#f7faff] p-4">
          <div className="mb-3 flex items-center gap-2 text-[11px] font-semibold text-foreground"><span className="size-2 rounded-full bg-[var(--low)]" />System online</div>
          <SystemStatus system={system} />
        </div>
      </aside>

      <div className="min-w-0 lg:col-start-2">
        <header className="sticky top-0 z-30 border-b border-border bg-white/92 backdrop-blur">
          <div className="flex h-[64px] items-center gap-3 px-4 md:px-7">
            <Link href="/" className="font-semibold lg:hidden">SentinelAI</Link>
            <form action="/threats" className="relative ml-auto w-full max-w-[360px]">
              <Search aria-hidden="true" className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-[var(--text-muted)]" />
              <input name="q" aria-label="Search threats" placeholder="Search alerts or employees" className="control w-full bg-[var(--surface-elevated)] pl-9 pr-3 placeholder:text-[var(--text-muted)]" />
            </form>
            <button aria-label="Notifications" className="grid size-9 place-items-center rounded-lg border border-border bg-white text-[var(--text-secondary)] hover:bg-[var(--surface-hover)]"><Bell className="size-4" /></button>
            <div className="hidden border-l border-border pl-4 sm:block"><span className="block text-[11px] font-semibold">Security Analyst</span><span className="text-[9px] text-[var(--text-muted)]">{system.data.label}</span></div>
          </div>
          <div className="border-t border-border lg:hidden"><SidebarNav compact /></div>
        </header>
        <main id="main-content" tabIndex={-1} className="px-4 py-6 md:px-7 md:py-7 xl:px-9 xl:py-8">{children}</main>
      </div>
    </div>
  );
}
