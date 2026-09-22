"use client";

import { useState } from "react";
import { ChevronDown, ChevronUp, Sliders, ShieldCheck, GitFork } from "lucide-react";

export function GraphMethodology() {
  const [openWorks, setOpenWorks] = useState(true);
  const [openParams, setOpenParams] = useState(false);
  const [openSafeguards, setOpenSafeguards] = useState(false);

  const parameters = [
    {
      name: "GRAPH_SHARED_DEVICE_MIN_EMPLOYEES",
      label: "Shared Device Minimum Employees",
      value: "2 employees",
      finding: "SHARED_DEVICE",
      explanation: "Minimum number of distinct employee accounts using a device in medium or higher risk contexts before triggering an alert.",
    },
    {
      name: "GRAPH_SHARED_IP_MIN_EMPLOYEES",
      label: "Shared IP Minimum Employees",
      value: "3 employees",
      finding: "SHARED_IP",
      explanation: "Minimum number of distinct employees connecting from an external/untrusted IP address during high-risk security activity.",
    },
    {
      name: "GRAPH_FILE_CONVERGENCE_WINDOW_MINUTES",
      label: "File Convergence Window",
      value: "15 minutes",
      finding: "SENSITIVE_FILE_CONVERGENCE",
      explanation: "Temporal window within which multiple accounts accessing the same Confidential or Restricted file triggers a convergence alert.",
    },
    {
      name: "GRAPH_SHARED_ENTITY_WINDOW_MINUTES",
      label: "Shared Entity Time Window",
      value: "60 minutes",
      finding: "MULTI_USER_SUSPICIOUS_INFRASTRUCTURE",
      explanation: "Maximum elapsed time between high-risk events sharing both the same physical device and IP address across different users.",
    },
    {
      name: "GRAPH_HIGH_RISK_EVENT_RATIO_THRESHOLD",
      label: "High-Risk Event Ratio Threshold",
      value: "50% (0.50)",
      finding: "HIGH_RISK_ENTITY",
      explanation: "Minimum proportion of total events associated with a device, IP, or file that must be High or Critical risk (minimum 3 events).",
    },
    {
      name: "ENABLE_GRAPH_RISK_CONTRIBUTION",
      label: "Production Risk Isolation Guardrail",
      value: "False (Supplementary)",
      finding: "Risk Engine Guardrail",
      explanation: "Strict isolation guardrail ensuring graph findings remain supplementary evidence and never distort baseline production risk scores.",
    },
  ];

  return (
    <div className="space-y-4">
      {/* 1. How Graph Analysis Works (Requirement 30) */}
      <div className="bg-[var(--surface)] border border-[var(--border)] rounded-lg overflow-hidden shadow-xs">
        <button
          type="button"
          onClick={() => setOpenWorks(!openWorks)}
          className="w-full p-4 flex items-center justify-between text-left hover:bg-[var(--surface-hover)] transition-colors"
        >
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-md bg-blue-50 text-blue-600 border border-blue-200">
              <GitFork className="size-4" />
            </div>
            <div>
              <h3 className="font-semibold text-sm text-[var(--foreground)]">How Graph Analysis Works</h3>
              <p className="text-xs text-[var(--text-secondary)]">
                Multi-entity relationship correlation architecture and analysis pipeline
              </p>
            </div>
          </div>
          {openWorks ? <ChevronUp className="size-4 text-[var(--text-muted)]" /> : <ChevronDown className="size-4 text-[var(--text-muted)]" />}
        </button>

        {openWorks && (
          <div className="p-4 pt-1 border-t border-[var(--border)] text-xs text-[var(--text-secondary)] space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-5 gap-2 pt-2">
              <div className="p-3 bg-[var(--surface-elevated)] border border-[var(--border)] rounded-md">
                <div className="font-bold text-[var(--accent)] text-[11px] uppercase tracking-wider mb-1">1. Entity Extraction</div>
                <p className="text-[11px] leading-relaxed">
                  Employees, Activity Events, Devices, IP Addresses, Locations, Files, and Attack Runs are ingested into in-memory frozen nodes.
                </p>
              </div>

              <div className="p-3 bg-[var(--surface-elevated)] border border-[var(--border)] rounded-md">
                <div className="font-bold text-indigo-600 text-[11px] uppercase tracking-wider mb-1">2. Event Traceability</div>
                <p className="text-[11px] leading-relaxed">
                  Event nodes serve as first-class intermediaries (<code className="text-[10px]">GENERATED</code>, <code className="text-[10px]">USED_DEVICE</code>, <code className="text-[10px]">CONNECTED_FROM</code>).
                </p>
              </div>

              <div className="p-3 bg-[var(--surface-elevated)] border border-[var(--border)] rounded-md">
                <div className="font-bold text-amber-600 text-[11px] uppercase tracking-wider mb-1">3. Correlation Engine</div>
                <p className="text-[11px] leading-relaxed">
                  Cross-account infrastructure reuse, rapid file convergence, and attack telemetry clusters are detected deterministically.
                </p>
              </div>

              <div className="p-3 bg-[var(--surface-elevated)] border border-[var(--border)] rounded-md">
                <div className="font-bold text-orange-600 text-[11px] uppercase tracking-wider mb-1">4. Graph Findings</div>
                <p className="text-[11px] leading-relaxed">
                  Explainable findings with explicit entity IDs and supporting telemetry event references are synthesized for analysts.
                </p>
              </div>

              <div className="p-3 bg-[var(--surface-elevated)] border border-[var(--border)] rounded-md">
                <div className="font-bold text-emerald-600 text-[11px] uppercase tracking-wider mb-1">5. Analyst Context</div>
                <p className="text-[11px] leading-relaxed">
                  Supplementary visualization and findings assist triage without modifying validated production risk scoring values.
                </p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 2. Detection Parameters (Requirement 31) */}
      <div className="bg-[var(--surface)] border border-[var(--border)] rounded-lg overflow-hidden shadow-xs">
        <button
          type="button"
          onClick={() => setOpenParams(!openParams)}
          className="w-full p-4 flex items-center justify-between text-left hover:bg-[var(--surface-hover)] transition-colors"
        >
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-md bg-purple-50 text-purple-600 border border-purple-200">
              <Sliders className="size-4" />
            </div>
            <div>
              <h3 className="font-semibold text-sm text-[var(--foreground)]">Detection Parameters Reference</h3>
              <p className="text-xs text-[var(--text-secondary)]">
                Active thresholds and temporal window configurations in production
              </p>
            </div>
          </div>
          {openParams ? <ChevronUp className="size-4 text-[var(--text-muted)]" /> : <ChevronDown className="size-4 text-[var(--text-muted)]" />}
        </button>

        {openParams && (
          <div className="p-4 pt-1 border-t border-[var(--border)] overflow-x-auto text-xs">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-[var(--border)] text-[var(--text-secondary)] font-semibold text-[11px]">
                  <th className="py-2 font-medium">Parameter</th>
                  <th className="py-2 font-medium">Configured Value</th>
                  <th className="py-2 font-medium">Triggered Rule</th>
                  <th className="py-2 font-medium">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)]">
                {parameters.map((p) => (
                  <tr key={p.name} className="hover:bg-[var(--surface-hover)]">
                    <td className="py-2.5 pr-4 align-top font-mono text-[10.5px] text-[var(--foreground)] font-semibold">
                      {p.name}
                    </td>
                    <td className="py-2.5 pr-4 align-top font-medium text-[var(--accent)] whitespace-nowrap">
                      {p.value}
                    </td>
                    <td className="py-2.5 pr-4 align-top">
                      <span className="px-1.5 py-0.5 rounded bg-[var(--surface-elevated)] border border-[var(--border)] text-[10px] font-mono text-[var(--text-secondary)]">
                        {p.finding}
                      </span>
                    </td>
                    <td className="py-2.5 align-top text-[11.5px] text-[var(--text-secondary)] leading-relaxed">
                      {p.explanation}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* 3. False-Positive Safeguards (Requirement 32) */}
      <div className="bg-[var(--surface)] border border-[var(--border)] rounded-lg overflow-hidden shadow-xs">
        <button
          type="button"
          onClick={() => setOpenSafeguards(!openSafeguards)}
          className="w-full p-4 flex items-center justify-between text-left hover:bg-[var(--surface-hover)] transition-colors"
        >
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-md bg-emerald-50 text-emerald-600 border border-emerald-200">
              <ShieldCheck className="size-4" />
            </div>
            <div>
              <h3 className="font-semibold text-sm text-[var(--foreground)]">Enterprise False-Positive Safeguards</h3>
              <p className="text-xs text-[var(--text-secondary)]">
                Architecture guardrails distinguishing benign shared infrastructure from adversarial behavior
              </p>
            </div>
          </div>
          {openSafeguards ? <ChevronUp className="size-4 text-[var(--text-muted)]" /> : <ChevronDown className="size-4 text-[var(--text-muted)]" />}
        </button>

        {openSafeguards && (
          <div className="p-4 pt-1 border-t border-[var(--border)] text-xs text-[var(--text-secondary)] leading-relaxed space-y-3">
            <p className="p-3 bg-emerald-50/60 border border-emerald-200 rounded-md text-emerald-950 font-medium text-[11.5px]">
              <strong>Enterprise Safeguard Principle:</strong> Shared infrastructure is <strong>not</strong> classified as High or Critical solely because multiple employees use it. SentinelAI accounts for legitimate corporate NAT gateways, VPN concentrators, proxies, and shared conference room workstations.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
              <div className="p-3 bg-[var(--surface-elevated)] border border-[var(--border)] rounded-md">
                <strong className="block text-[var(--foreground)] text-xs mb-1">Corporate NAT / VPN Handling</strong>
                <p className="text-[11px] text-[var(--text-secondary)]">
                  Approved corporate IP ranges (<code className="text-[10px]">10.0.0.1</code>, <code className="text-[10px]">172.16.0.1</code>) shared normally produce only <span className="font-semibold text-blue-700">Informational</span> context.
                </p>
              </div>

              <div className="p-3 bg-[var(--surface-elevated)] border border-[var(--border)] rounded-md">
                <strong className="block text-[var(--foreground)] text-xs mb-1">Shared Workstations & Devices</strong>
                <p className="text-[11px] text-[var(--text-secondary)]">
                  Shared devices remain informational unless explicitly correlated with confirmed medium, high, or critical anomalous telemetry events.
                </p>
              </div>

              <div className="p-3 bg-[var(--surface-elevated)] border border-[var(--border)] rounded-md">
                <strong className="block text-[var(--foreground)] text-xs mb-1">Evidence Corroboration Requirement</strong>
                <p className="text-[11px] text-[var(--text-secondary)]">
                  High-severity graph findings require corroboration: multiple high-risk activity events, anomalous time windows, and unapproved external infrastructure.
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
