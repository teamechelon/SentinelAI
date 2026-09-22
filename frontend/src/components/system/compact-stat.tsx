import type { RiskLevel } from "@/domain/sentinel";
import { severityTextClass } from "@/lib/presentation";
import { cn } from "@/lib/utils";

export function CompactStat({ label, value, risk }: { label: string; value: string | number; risk?: RiskLevel }) {
  return (
    <div className="min-w-0 border-l border-border px-4 py-2 first:border-l-0 first:pl-0">
      <div className={cn("tabular truncate font-mono text-[20px] font-semibold leading-none", risk && severityTextClass[risk])}>{value}</div>
      <div className="mt-1.5 tech-label">{label}</div>
    </div>
  );
}
