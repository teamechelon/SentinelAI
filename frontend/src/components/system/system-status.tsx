import type { SystemStatusSnapshot } from "@/domain/sentinel";

function StatusLine({ label, value, ready = false }: { label: string; value: string; ready?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3 py-1.5 text-[11px]">
      <span className="text-[var(--text-muted)]">{label}</span>
      <span className="flex items-center gap-1.5 font-mono text-[10px] uppercase text-[var(--text-secondary)]">
        <span aria-hidden="true" className={`size-1.5 rounded-full ${ready ? "bg-[var(--low)]" : "bg-[var(--text-muted)]"}`} />
        {value}
      </span>
    </div>
  );
}

export function SystemStatus({ system }: { system: SystemStatusSnapshot }) {
  return (
    <div aria-label="Detection system status">
      <StatusLine label="Model" value={system.model.status} ready={system.model.status === "ready"} />
      <StatusLine label="Database" value={system.database.status} ready={system.database.status === "ready"} />
      <StatusLine label="Data" value={system.data.label} />
    </div>
  );
}
