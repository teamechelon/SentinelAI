"use client";

import { useState, useTransition } from "react";
import { Info, KeyRound, LockKeyhole, RotateCcw, ShieldCheck, ShieldX, X } from "lucide-react";
import { performContainmentAction } from "@/app/threats/actions";
import type { ContainmentState, MitreReport, ResponseAction, ResponseAudit, ThreatSummary } from "@/domain/sentinel";
import { cn } from "@/lib/utils";

const actionLabels: Record<ResponseAction, string> = {
  BLOCK_USER: "Block User",
  UNBLOCK_USER: "Unblock User",
  REVOKE_SESSIONS: "Revoke Sessions",
  RESTORE_SESSIONS: "Restore Sessions",
  BLOCK_AND_REVOKE: "Block + Revoke",
};

const actionIcons: Record<ResponseAction, typeof LockKeyhole> = {
  BLOCK_USER: LockKeyhole,
  UNBLOCK_USER: ShieldCheck,
  REVOKE_SESSIONS: KeyRound,
  RESTORE_SESSIONS: RotateCcw,
  BLOCK_AND_REVOKE: ShieldX,
};

const responseTimestamp = new Intl.DateTimeFormat("en-GB", {
  dateStyle: "medium",
  timeStyle: "medium",
  timeZone: "UTC",
});

function formatResponseTimestamp(value: string) {
  return `${responseTimestamp.format(new Date(value))} UTC`;
}

function validActions(state: ContainmentState): ResponseAction[] {
  const actions: ResponseAction[] = [];
  if (state.accountStatus === "ACTIVE") actions.push("BLOCK_USER");
  else actions.push("UNBLOCK_USER");
  if (state.sessionStatus === "ACTIVE") actions.push("REVOKE_SESSIONS");
  else actions.push("RESTORE_SESSIONS");
  if (state.accountStatus === "ACTIVE" && state.sessionStatus === "ACTIVE") actions.push("BLOCK_AND_REVOKE");
  return actions;
}

function StatusBadge({ value, tone }: { value: string; tone: "green" | "red" | "amber" | "blue" | "neutral" }) {
  const colors = {
    green: "border-[#b8dec6] bg-[#edf8f1] text-[#217346]",
    red: "border-[#f2c1c5] bg-[#fff0f1] text-[#b4232f]",
    amber: "border-[#efd6a8] bg-[#fff8e8] text-[#986514]",
    blue: "border-[#c7d8f5] bg-[#eef4ff] text-[#315d9d]",
    neutral: "border-border bg-[var(--surface-elevated)] text-[var(--text-secondary)]",
  };
  return <span className={cn("inline-flex rounded-full border px-2 py-1 text-[9px] font-bold tracking-[0.08em]", colors[tone])}>{value}</span>;
}

function statusTone(value: string) {
  if (value === "ACTIVE") return "green" as const;
  if (value === "BLOCKED") return "red" as const;
  if (value === "REVOKED") return "amber" as const;
  if (value === "AUTO" || value === "MANUAL") return "blue" as const;
  return "neutral" as const;
}

export function ContainmentPanel({
  threat,
  initialState,
  initialHistory,
  mitre,
}: {
  threat: ThreatSummary;
  initialState: ContainmentState;
  initialHistory: ResponseAudit[];
  mitre: MitreReport | null;
}) {
  const [state, setState] = useState(initialState);
  const [history, setHistory] = useState(initialHistory);
  const [selected, setSelected] = useState<ResponseAction | null>(null);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  function submit() {
    if (!selected) return;
    setError(null);
    startTransition(async () => {
      const result = await performContainmentAction({
        employeeId: threat.employeeId,
        alertId: threat.alertId,
        action: selected,
        reason,
      });
      if (!result.ok || !result.state) {
        setError(result.error ?? "Containment action could not be completed.");
        return;
      }
      setState(result.state);
      if (result.history) setHistory(result.history.items);
      setSelected(null);
      setReason("");
    });
  }

  return (
    <section className="space-y-4" aria-labelledby="containment-title">
      <div className="flex gap-3 rounded-xl border border-[#c9dcf5] bg-[#f3f7fd] p-4 text-[#244d7d]">
        <Info className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
        <div><h2 className="text-[11px] font-bold">Simulated Containment</h2><p className="mt-1 text-[10px] leading-5">SentinelAI is not currently connected to an enterprise identity or endpoint provider. Containment actions are applied only inside SentinelAI to demonstrate the response workflow.</p></div>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.15fr_0.85fr]">
        <article className="panel p-5">
          <div className="flex flex-wrap items-start justify-between gap-3"><div><div className="tech-label">Response Policy</div><h2 id="containment-title" className="mt-2 text-[16px] font-bold">Containment Status</h2></div><StatusBadge value={state.containmentStatus} tone={state.containmentStatus === "CONTAINED" ? "red" : state.containmentStatus === "PARTIAL" ? "amber" : "green"} /></div>
          <dl className="mt-5 grid gap-x-5 gap-y-4 sm:grid-cols-2 lg:grid-cols-3">
            <StatusField label="Account Status"><StatusBadge value={state.accountStatus} tone={statusTone(state.accountStatus)} /></StatusField>
            <StatusField label="Session Status"><StatusBadge value={state.sessionStatus} tone={statusTone(state.sessionStatus)} /></StatusField>
            <StatusField label="Containment Mode">{state.containmentMode ? <StatusBadge value={state.containmentMode} tone={statusTone(state.containmentMode)} /> : "—"}</StatusField>
            <StatusField label="Risk at Trigger">{state.riskScoreAtAction === null ? "—" : `${state.riskScoreAtAction.toFixed(0)} / 100`}</StatusField>
            <StatusField label="Trigger">{state.containmentMode === "AUTO" ? "Automatic Response Policy" : state.containmentMode === "MANUAL" ? "Manual Analyst Action" : "No containment action"}</StatusField>
            <StatusField label="Contained At">{state.containedAt ? formatResponseTimestamp(state.containedAt) : "—"}</StatusField>
            <StatusField label="Source Alert">{state.sourceAlertId ?? "—"}</StatusField>
            <StatusField label="Last Action">{state.lastAction ? actionLabels[state.lastAction] : "—"}</StatusField>
            <StatusField label="Actor">{state.containedBy ?? "—"}</StatusField>
          </dl>
          <div className="mt-5 border-t border-border pt-4"><div className="tech-label">Reason for response</div><p className="mt-2 text-[11px] leading-5 text-[var(--text-secondary)]">{state.reason ?? "No containment action has been recorded for this employee."}</p></div>
          {mitre && <div className="mt-4 grid gap-4 border-t border-border pt-4 md:grid-cols-2"><div><div className="tech-label">Threat Story</div><p className="mt-2 text-[11px] font-semibold">{mitre.threatStory.title}</p><p className="mt-1 text-[10px] leading-5 text-[var(--text-secondary)]">{mitre.threatStory.summary}</p></div><div><div className="tech-label">MITRE Techniques</div><div className="mt-2 flex flex-wrap gap-1.5">{mitre.mappings.length ? mitre.mappings.map((mapping) => <span key={mapping.techniqueId} className="rounded border border-border bg-[var(--surface-elevated)] px-2 py-1 font-mono text-[9px]">{mapping.techniqueId} · {mapping.techniqueName}</span>) : <span className="text-[10px] text-[var(--text-muted)]">No evidence-backed mapping</span>}</div></div></div>}
        </article>

        <article className="panel p-5">
          <div className="tech-label">Analyst Controls</div><h2 className="mt-2 text-[16px] font-bold">Containment Actions</h2><p className="mt-1 text-[10px] leading-5 text-[var(--text-secondary)]">Actions update the internal SentinelAI simulation only. Confirmation and an analyst reason are required.</p>
          <div className="mt-5 grid gap-2 sm:grid-cols-2 xl:grid-cols-1 2xl:grid-cols-2">{validActions(state).map((action) => { const Icon = actionIcons[action]; return <button key={action} type="button" onClick={() => { setSelected(action); setError(null); }} className={cn("inline-flex min-h-10 items-center justify-center gap-2 rounded-lg border px-3 text-[10px] font-bold transition-colors", action === "BLOCK_AND_REVOKE" ? "border-[#e7b8bd] bg-[#fff5f5] text-[#a82430] hover:bg-[#ffebed]" : "border-border bg-white text-foreground hover:bg-[var(--surface-hover)]")}><Icon className="size-3.5" aria-hidden="true" />{actionLabels[action]}</button>; })}</div>
          <p className="mt-4 text-[9px] leading-4 text-[var(--text-muted)]">Only actions valid for the current account and session state are available.</p>
        </article>
      </div>

      <article className="panel overflow-hidden">
        <div className="border-b border-border px-5 py-4"><div className="tech-label">Immutable Audit Trail</div><h2 className="mt-2 text-[16px] font-bold">Response History</h2></div>
        {history.length ? <div className="overflow-x-auto"><table className="w-full min-w-[880px] text-left"><thead className="bg-[var(--surface-elevated)]"><tr>{["Timestamp", "Action", "Mode", "Actor", "Alert", "Risk", "Reason", "Result"].map((label) => <th key={label} className="h-9 px-3 tech-label">{label}</th>)}</tr></thead><tbody className="divide-y divide-border">{history.map((item) => <tr key={item.actionId} className="text-[10px]"><td className="px-3 py-3 font-mono text-[var(--text-secondary)]">{formatResponseTimestamp(item.createdAt)}</td><td className="px-3 py-3 font-mono font-semibold">{item.action}</td><td className="px-3 py-3"><StatusBadge value={item.mode} tone="blue" /></td><td className="px-3 py-3">{item.actor}</td><td className="px-3 py-3 font-mono">{item.alertId ?? "—"}</td><td className="px-3 py-3 tabular">{item.riskScoreAtAction ?? "—"}</td><td className="max-w-[260px] px-3 py-3 text-[var(--text-secondary)]">{item.reason}</td><td className="px-3 py-3"><StatusBadge value={item.result} tone={item.result === "SUCCESS" ? "green" : "red"} /></td></tr>)}</tbody></table></div> : <div className="px-5 py-10 text-center text-[10px] text-[var(--text-muted)]">No response actions recorded.</div>}
      </article>

      {selected && <div className="fixed inset-0 z-50 grid place-items-center bg-[#10233d]/30 p-4" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !isPending) setSelected(null); }}><div role="dialog" aria-modal="true" aria-labelledby="confirmation-title" className="w-full max-w-md rounded-2xl border border-border bg-white p-5 shadow-2xl"><div className="flex items-start justify-between gap-4"><div><div className="tech-label">Confirmation Required</div><h2 id="confirmation-title" className="mt-2 text-[16px] font-bold">{actionLabels[selected]} in SentinelAI?</h2></div><button type="button" aria-label="Close confirmation" disabled={isPending} onClick={() => setSelected(null)} className="rounded-md p-1 text-[var(--text-muted)] hover:bg-[var(--surface-hover)]"><X className="size-4" /></button></div><dl className="mt-5 grid grid-cols-[90px_1fr] gap-y-2 text-[10px]"><dt className="text-[var(--text-muted)]">Employee</dt><dd className="font-semibold">{threat.employeeName} · {threat.employeeId}</dd><dt className="text-[var(--text-muted)]">Alert</dt><dd className="font-mono">{threat.alertId}</dd><dt className="text-[var(--text-muted)]">Current Risk</dt><dd className="font-semibold">{threat.riskScore.toFixed(0)} / 100 · {threat.riskLevel}</dd></dl><label htmlFor="containment-reason" className="mt-5 block text-[10px] font-bold">Analyst reason</label><textarea id="containment-reason" autoFocus maxLength={240} value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Example: Confirmed account compromise" className="mt-2 min-h-24 w-full resize-y rounded-lg border border-border bg-white px-3 py-2 text-[11px] outline-none focus:border-[var(--accent)]" />{error && <p role="alert" className="mt-2 text-[10px] text-[var(--critical)]">{error}</p>}<div className="mt-5 flex justify-end gap-2"><button type="button" disabled={isPending} onClick={() => setSelected(null)} className="rounded-lg border border-border px-4 py-2 text-[10px] font-bold hover:bg-[var(--surface-hover)]">Cancel</button><button type="button" disabled={isPending || !reason.trim()} onClick={submit} className="rounded-lg bg-[var(--accent)] px-4 py-2 text-[10px] font-bold text-white disabled:cursor-not-allowed disabled:opacity-50">{isPending ? "Applying…" : `Confirm ${actionLabels[selected]}`}</button></div></div></div>}
    </section>
  );
}

function StatusField({ label, children }: { label: string; children: React.ReactNode }) {
  return <div><dt className="tech-label">{label}</dt><dd className="mt-2 min-h-5 text-[10px] font-semibold text-foreground">{children}</dd></div>;
}
