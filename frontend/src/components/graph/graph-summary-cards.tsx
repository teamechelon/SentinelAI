"use client";

import { useState } from "react";
import { HelpCircle, Network, Share2, ShieldAlert, AlertTriangle, Laptop, Globe } from "lucide-react";
import type { GraphOverview, GraphFinding } from "@/domain/sentinel";

interface GraphSummaryCardsProps {
  overview: GraphOverview;
  findings: GraphFinding[];
}

interface MetricTooltipProps {
  title: string;
  meaning: string;
  calculation: string;
}

function MetricTooltip({ title, meaning, calculation }: MetricTooltipProps) {
  const [open, setOpen] = useState(false);

  return (
    <div className="relative inline-block ml-1.5 align-middle">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        onMouseEnter={() => setOpen(true)}
        onMouseLeave={() => setOpen(false)}
        className="text-[var(--text-muted)] hover:text-[var(--accent)] transition-colors focus:outline-none"
        aria-label={`Calculation details for ${title}`}
      >
        <HelpCircle className="size-3.5" />
      </button>

      {open && (
        <div className="absolute left-1/2 -translate-x-1/2 bottom-full mb-2 z-50 w-72 p-3 bg-[var(--surface)] border border-[var(--border-strong)] rounded-lg shadow-xl text-left text-xs space-y-2 pointer-events-none animate-in fade-in zoom-in-95 duration-150">
          <div>
            <div className="font-semibold text-[var(--foreground)]">{title}</div>
            <div className="text-[10px] text-[var(--text-muted)]">Calculation Reference</div>
          </div>
          <div className="border-t border-[var(--border)] pt-1.5 space-y-1">
            <div>
              <span className="font-medium text-[var(--text-secondary)]">What does this mean?</span>
              <p className="text-[11px] text-[var(--text-secondary)] leading-relaxed mt-0.5">{meaning}</p>
            </div>
            <div className="pt-1">
              <span className="font-medium text-[var(--text-secondary)]">How is this calculated?</span>
              <p className="text-[11px] text-[var(--text-secondary)] leading-relaxed mt-0.5">{calculation}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export function GraphSummaryCards({ overview, findings }: GraphSummaryCardsProps) {
  const sharedDevicesCount = findings.filter(f => f.findingType === "SHARED_DEVICE").length || (overview.entityCounts.device ?? 0);
  const sharedIpsCount = findings.filter(f => f.findingType === "SHARED_IP").length || (overview.entityCounts.ip_address ?? 0);

  const cards = [
    {
      title: "Total Entities",
      value: overview.nodeCount,
      description: "Across 8 entity categories",
      icon: Network,
      iconColor: "text-blue-600 bg-blue-50 border-blue-200",
      accent: false,
      tooltip: {
        meaning: "Total unique nodes currently represented in the SentinelAI security knowledge graph.",
        calculation: "Aggregated count of employees, events, devices, IP addresses, locations, files, departments, and attack simulation runs.",
      },
    },
    {
      title: "Total Relationships",
      value: overview.edgeCount,
      description: "Correlated telemetry links",
      icon: Share2,
      iconColor: "text-indigo-600 bg-indigo-50 border-indigo-200",
      accent: false,
      tooltip: {
        meaning: "Direct behavioral and infrastructure relationships connecting entities.",
        calculation: "Includes GENERATED, USED_DEVICE, CONNECTED_FROM, OCCURRED_AT, ACCESSED_FILE, and PART_OF_ATTACK_RUN edges.",
      },
    },
    {
      title: "Security Findings",
      value: overview.findingCount,
      description: "Graph correlation alerts",
      icon: ShieldAlert,
      iconColor: "text-amber-600 bg-amber-50 border-amber-200",
      accent: false,
      tooltip: {
        meaning: "Explainable multi-entity suspicious activity patterns identified by graph correlation algorithms.",
        calculation: "Total active findings detected across SHARED_DEVICE, SHARED_IP, MULTI_USER, CONVERGENCE, CLUSTER, and HIGH_RISK rules.",
      },
    },
    {
      title: "High-Severity Findings",
      value: overview.highSeverityFindingCount,
      description: "Requiring security analyst review",
      icon: AlertTriangle,
      iconColor: "text-red-600 bg-red-50 border-red-200",
      accent: true,
      tooltip: {
        meaning: "Graph findings categorized as High or Critical based on confirmed high-risk telemetry events.",
        calculation: "Findings involving confirmed high-risk anomalous behavior, impossible travel, or verified attack infrastructure reuse.",
      },
    },
    {
      title: "Suspicious Shared Devices",
      value: sharedDevicesCount,
      description: "Multi-user workstations",
      icon: Laptop,
      iconColor: "text-teal-600 bg-teal-50 border-teal-200",
      accent: false,
      tooltip: {
        meaning: "Physical or virtual devices accessed by multiple employees with concurrent medium or high risk activity.",
        calculation: "Triggered when >= 2 employees share a device and at least one connecting event has risk >= 30, excluding approved common corporate assets.",
      },
    },
    {
      title: "Suspicious Shared IPs",
      value: sharedIpsCount,
      description: "Multi-user network endpoints",
      icon: Globe,
      iconColor: "text-cyan-600 bg-cyan-50 border-cyan-200",
      accent: false,
      tooltip: {
        meaning: "External or internal IP addresses shared across multiple employee accounts during elevated risk events.",
        calculation: "Triggered when >= 3 employees share an IP address with high/critical risk events, excluding trusted corporate gateways.",
      },
    },
  ];

  return (
    <div className="grid grid-cols-2 gap-3.5 sm:grid-cols-3 lg:grid-cols-6">
      {cards.map((c) => {
        const Icon = c.icon;
        return (
          <div
            key={c.title}
            className="panel p-3.5 bg-[var(--surface)] border border-[var(--border)] rounded-lg shadow-xs hover:border-[var(--border-strong)] transition-all flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="tech-label text-[10px] tracking-wider text-[var(--text-secondary)] font-medium">
                  {c.title}
                </span>
                <div className={`p-1.5 rounded-md border text-xs ${c.iconColor}`}>
                  <Icon className="size-3.5" />
                </div>
              </div>
              <div className="flex items-center">
                <span className={`text-[26px] font-bold tracking-tight tabular ${c.accent ? "text-[var(--critical)]" : "text-[var(--foreground)]"}`}>
                  {c.value.toLocaleString()}
                </span>
                <MetricTooltip
                  title={c.title}
                  meaning={c.tooltip.meaning}
                  calculation={c.tooltip.calculation}
                />
              </div>
            </div>
            <div className="mt-2 text-[10.5px] text-[var(--text-muted)] border-t border-[var(--border)] pt-2 truncate">
              {c.description}
            </div>
          </div>
        );
      })}
    </div>
  );
}
