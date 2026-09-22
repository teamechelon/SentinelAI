"use client";

import { AlertTriangle, Info, CheckCircle, ExternalLink } from "lucide-react";
import type { GraphFinding } from "@/domain/sentinel";

interface GraphFindingsTableProps {
  findings: GraphFinding[];
  selectedFinding?: GraphFinding | null;
  onSelectFinding?: (finding: GraphFinding) => void;
}

export function GraphFindingsTable({
  findings,
  selectedFinding,
  onSelectFinding,
}: GraphFindingsTableProps) {
  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return {
          icon: AlertTriangle,
          badgeClass: "bg-red-50 text-red-700 border-red-200",
          iconClass: "text-red-600",
        };
      case "high":
        return {
          icon: AlertTriangle,
          badgeClass: "bg-orange-50 text-orange-700 border-orange-200",
          iconClass: "text-orange-600",
        };
      case "medium":
        return {
          icon: Info,
          badgeClass: "bg-amber-50 text-amber-700 border-amber-200",
          iconClass: "text-amber-600",
        };
      case "low":
        return {
          icon: CheckCircle,
          badgeClass: "bg-emerald-50 text-emerald-700 border-emerald-200",
          iconClass: "text-emerald-600",
        };
      default:
        return {
          icon: Info,
          badgeClass: "bg-slate-100 text-slate-700 border-slate-200",
          iconClass: "text-slate-500",
        };
    }
  };

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
          <tr className="border-b border-[var(--border)] text-[var(--text-secondary)] font-semibold text-[11px]">
            <th className="pb-2.5 pl-2 font-medium w-28">Severity</th>
            <th className="pb-2.5 font-medium w-48">Correlation Rule</th>
            <th className="pb-2.5 font-medium">Involved Entities</th>
            <th className="pb-2.5 font-medium">Supporting Evidence</th>
            <th className="pb-2.5 font-medium">Explanation</th>
            <th className="pb-2.5 pr-2 font-medium text-right w-24">Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--border)]">
          {findings.map((f, idx) => {
            const { icon: SeverityIcon, badgeClass, iconClass } = getSeverityBadge(f.severity);
            const isSelected = selectedFinding === f;

            return (
              <tr
                key={idx}
                className={`group transition-colors ${
                  isSelected ? "bg-[var(--accent-dim)]" : "hover:bg-[var(--surface-hover)]"
                }`}
              >
                {/* Severity */}
                <td className="py-3 pl-2 pr-3 align-top">
                  <span
                    className={`inline-flex items-center gap-1 rounded-sm px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border ${badgeClass}`}
                  >
                    <SeverityIcon className={`size-3 ${iconClass}`} />
                    {f.severity}
                  </span>
                </td>

                {/* Finding Type */}
                <td className="py-3 pr-3 align-top">
                  <div className="font-semibold text-[var(--foreground)]">{humanize(f.findingType)}</div>
                  <div className="text-[10px] text-[var(--text-muted)] truncate max-w-[180px]">
                    {f.observedRelationship}
                  </div>
                </td>

                {/* Entities Involved */}
                <td className="py-3 pr-3 align-top">
                  <div className="flex flex-wrap gap-1 max-w-[280px]">
                    {f.entities.slice(0, 5).map((e, i) => (
                      <span
                        key={i}
                        className="rounded border border-[var(--border)] bg-[var(--surface-elevated)] px-1.5 py-0.5 text-[10px] font-mono text-[var(--text-secondary)]"
                      >
                        {e}
                      </span>
                    ))}
                    {f.entities.length > 5 && (
                      <span className="text-[10px] text-[var(--text-muted)] self-center">
                        +{f.entities.length - 5}
                      </span>
                    )}
                  </div>
                </td>

                {/* Supporting Events */}
                <td className="py-3 pr-3 align-top">
                  {f.supportingEvents.length > 0 ? (
                    <div className="flex flex-wrap gap-1 max-w-[200px]">
                      {f.supportingEvents.slice(0, 3).map((eid, i) => (
                        <span
                          key={i}
                          className="rounded border border-[var(--border)] bg-slate-50 px-1.5 py-0.5 text-[9.5px] font-mono text-slate-600"
                        >
                          {eid}
                        </span>
                      ))}
                      {f.supportingEvents.length > 3 && (
                        <span className="text-[9.5px] text-[var(--text-muted)] self-center">
                          +{f.supportingEvents.length - 3}
                        </span>
                      )}
                    </div>
                  ) : (
                    <span className="text-[10.5px] text-[var(--text-muted)] italic">N/A</span>
                  )}
                </td>

                {/* Explanation */}
                <td className="py-3 pr-3 align-top text-[11.5px] text-[var(--text-secondary)] leading-relaxed max-w-sm">
                  {f.explanation}
                </td>

                {/* Interactive Highlight Action */}
                <td className="py-3 pr-2 align-top text-right">
                  {onSelectFinding && (
                    <button
                      type="button"
                      onClick={() => onSelectFinding(f)}
                      className={`inline-flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium transition-colors ${
                        isSelected
                          ? "bg-[var(--accent)] text-white shadow-xs"
                          : "text-[var(--accent)] hover:bg-[var(--surface-elevated)] border border-[var(--border)]"
                      }`}
                      title="Highlight involved entities in graph visualization"
                    >
                      <ExternalLink className="size-3" />
                      <span>{isSelected ? "Active" : "Highlight"}</span>
                    </button>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
