"use client";

import type { GraphFinding } from "@/domain/sentinel";
import { cn } from "@/lib/utils";

const SEVERITY_COLORS: Record<string, string> = {
  informational: "text-[var(--text-muted)] bg-[var(--surface-elevated)]",
  low: "text-[var(--low)] bg-green-50",
  medium: "text-[var(--medium)] bg-amber-50",
  high: "text-[var(--high)] bg-orange-50",
  critical: "text-[var(--critical)] bg-red-50",
};

export function GraphFindingsTable({ findings }: { findings: GraphFinding[] }) {
  const humanize = (str: string) => {
    return str
      .split("_")
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join(" ");
  };

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs">
        <thead>
          <tr className="border-b border-[var(--border)] text-[var(--text-secondary)]">
            <th className="pb-2 font-medium">Severity</th>
            <th className="pb-2 font-medium">Type</th>
            <th className="pb-2 font-medium">Entities Involved</th>
            <th className="pb-2 font-medium">Explanation</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--border)]">
          {findings.map((finding, idx) => (
            <tr key={idx} className="group hover:bg-[var(--surface-hover)]">
              <td className="py-3 pr-4 align-top">
                <span
                  className={cn(
                    "inline-flex items-center rounded-sm px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider",
                    SEVERITY_COLORS[finding.severity]
                  )}
                >
                  {finding.severity}
                </span>
              </td>
              <td className="py-3 pr-4 align-top font-medium">
                {humanize(finding.findingType)}
              </td>
              <td className="py-3 pr-4 align-top">
                <div className="flex flex-wrap gap-1">
                  {finding.entities.map((entity, i) => (
                    <span
                      key={i}
                      className="rounded border border-[var(--border)] bg-[var(--surface-elevated)] px-1.5 py-0.5 text-[10px] text-[var(--text-secondary)]"
                    >
                      {entity}
                    </span>
                  ))}
                </div>
              </td>
              <td className="py-3 align-top text-[var(--text-secondary)]">
                {finding.explanation}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
