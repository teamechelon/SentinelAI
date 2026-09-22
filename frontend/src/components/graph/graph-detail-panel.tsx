"use client";

import { X, User, Activity, Laptop, Globe, MapPin, FileText, Building2, ShieldAlert, Target, ShieldCheck } from "lucide-react";
import type { GraphNode, GraphEdge, GraphFinding } from "@/domain/sentinel";
import { NODE_CONFIGS, getNodeRiskLevel } from "./graph-types";

interface GraphDetailPanelProps {
  node: GraphNode;
  edges: GraphEdge[];
  findings: GraphFinding[];
  onClose: () => void;
  onSelectRelatedNode?: (nodeId: string) => void;
  onFocusNode?: (node: GraphNode) => void;
}

function EntityIcon({ type, className }: { type: string; className?: string }) {
  switch (type) {
    case "employee": return <User className={className} />;
    case "event": return <Activity className={className} />;
    case "device": return <Laptop className={className} />;
    case "ip_address": return <Globe className={className} />;
    case "location": return <MapPin className={className} />;
    case "file": return <FileText className={className} />;
    case "department": return <Building2 className={className} />;
    case "attack_run": return <Target className={className} />;
    default: return <ShieldAlert className={className} />;
  }
}

export function GraphDetailPanel({
  node,
  edges,
  findings,
  onClose,
  onSelectRelatedNode,
  onFocusNode,
}: GraphDetailPanelProps) {
  const catConfig = NODE_CONFIGS[node.nodeType] || { label: node.nodeType, fill: "#64748b" };
  const riskLevel = getNodeRiskLevel(node);

  // Filter edges connected to this entity
  const connectedEdges = edges.filter((e) => e.sourceId === node.nodeId || e.targetId === node.nodeId);
  const neighborIds = Array.from(
    new Set(connectedEdges.map((e) => (e.sourceId === node.nodeId ? e.targetId : e.sourceId)))
  );

  // Associated findings
  const associatedFindings = findings.filter(
    (f) =>
      f.entities.includes(node.nodeId) ||
      f.entities.includes(node.label) ||
      f.supportingEvents.includes(node.nodeId.replace("event:", ""))
  );

  // Type-specific counts
  const deviceEdges = connectedEdges.filter((e) => e.edgeType === "USES_DEVICE");
  const ipEdges = connectedEdges.filter((e) => e.edgeType === "CONNECTS_FROM");
  const fileEdges = connectedEdges.filter((e) => e.edgeType === "ACCESSES_FILE");
  const eventEdges = connectedEdges.filter((e) => e.edgeType === "GENERATED" || e.sourceId.startsWith("event:") || e.targetId.startsWith("event:"));
  const attackEdges = connectedEdges.filter((e) => e.edgeType === "PART_OF_ATTACK_RUN" || e.edgeType === "ASSOCIATED_WITH_ATTACK");

  const highCriticalEventsCount = connectedEdges.filter((e) => {
    const lvl = e.metadata.risk_level;
    return lvl === "High" || lvl === "Critical";
  }).length;

  const isTrustedCorporate =
    Boolean(node.metadata.trusted) ||
    node.metadata.trusted === "true" ||
    node.metadata.trusted === 1 ||
    ["10.0.0.1", "10.0.0.2", "192.168.1.1", "172.16.0.1"].includes(node.label) ||
    ["CORPORATE-NAT-GW", "VPN-GATEWAY-01", "SHARED-PRINTER-01"].includes(node.label);

  return (
    <div className="bg-[var(--surface)] border border-[var(--border)] rounded-lg shadow-lg flex flex-col max-h-[620px] overflow-hidden animate-in fade-in zoom-in-95 duration-150">
      {/* Header */}
      <div className="p-3.5 border-b border-[var(--border)] bg-gradient-to-r from-[var(--surface-elevated)] to-[var(--surface)] flex items-start justify-between">
        <div className="flex items-start gap-2.5">
          <div
            className="p-2 rounded-md text-white shadow-xs shrink-0"
            style={{ backgroundColor: catConfig.fill }}
          >
            <EntityIcon type={node.nodeType} className="size-4" />
          </div>
          <div>
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.2 rounded bg-slate-100 text-slate-700">
                {catConfig.label}
              </span>
              {riskLevel && (
                <span
                  className={`text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.2 rounded ${
                    riskLevel === "Critical"
                      ? "bg-red-100 text-red-700 border border-red-200"
                      : riskLevel === "High"
                      ? "bg-orange-100 text-orange-700 border border-orange-200"
                      : riskLevel === "Medium"
                      ? "bg-amber-100 text-amber-700 border border-amber-200"
                      : "bg-emerald-100 text-emerald-700 border border-emerald-200"
                  }`}
                >
                  {riskLevel} Risk
                </span>
              )}
              {isTrustedCorporate && (
                <span className="text-[10px] font-semibold px-1.5 py-0.2 rounded bg-blue-50 text-blue-700 border border-blue-200 flex items-center gap-1">
                  <ShieldCheck className="size-3" /> Trusted Infra
                </span>
              )}
            </div>
            <h3 className="font-semibold text-sm text-[var(--foreground)] mt-1 break-all">
              {node.label}
            </h3>
            <div className="text-[10px] text-[var(--text-muted)] font-mono">{node.nodeId}</div>
          </div>
        </div>

        <button
          type="button"
          onClick={onClose}
          className="text-[var(--text-muted)] hover:text-[var(--foreground)] p-1 rounded hover:bg-[var(--surface-hover)] transition-colors"
          aria-label="Close inspector"
        >
          <X className="size-4" />
        </button>
      </div>

      {/* Content Body */}
      <div className="overflow-y-auto p-3.5 space-y-4 text-xs divide-y divide-[var(--border)]">
        {/* Quick Focus Action */}
        {onFocusNode && (
          <div className="pb-3">
            <button
              type="button"
              onClick={() => onFocusNode(node)}
              className="w-full py-1.5 px-3 bg-[var(--accent)] hover:bg-[var(--accent-strong)] text-white rounded-md font-medium text-xs flex items-center justify-center gap-1.5 shadow-xs transition-colors"
            >
              <Target className="size-3.5" />
              Focus {node.nodeType === "employee" ? "Employee Relationships" : "Entity Connections"}
            </button>
          </div>
        )}

        {/* Section 1: Overview Summary Stats */}
        <div className="pt-3 space-y-2">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
            Overview
          </div>
          <div className="grid grid-cols-2 gap-2 text-[11px]">
            <div className="p-2 rounded bg-[var(--surface-elevated)] border border-[var(--border)]">
              <span className="text-[var(--text-muted)] block text-[10px]">Connected Entities</span>
              <strong className="text-sm font-semibold text-[var(--foreground)]">{neighborIds.length}</strong>
            </div>
            <div className="p-2 rounded bg-[var(--surface-elevated)] border border-[var(--border)]">
              <span className="text-[var(--text-muted)] block text-[10px]">Relationship Links</span>
              <strong className="text-sm font-semibold text-[var(--foreground)]">{connectedEdges.length}</strong>
            </div>
            <div className="p-2 rounded bg-[var(--surface-elevated)] border border-[var(--border)]">
              <span className="text-[var(--text-muted)] block text-[10px]">Security Findings</span>
              <strong className={`text-sm font-semibold ${associatedFindings.length > 0 ? "text-amber-700" : "text-[var(--foreground)]"}`}>
                {associatedFindings.length}
              </strong>
            </div>
            <div className="p-2 rounded bg-[var(--surface-elevated)] border border-[var(--border)]">
              <span className="text-[var(--text-muted)] block text-[10px]">High/Critical Events</span>
              <strong className={`text-sm font-semibold ${highCriticalEventsCount > 0 ? "text-red-700" : "text-[var(--foreground)]"}`}>
                {highCriticalEventsCount}
              </strong>
            </div>
          </div>
        </div>

        {/* Section 2: Entity-Specific Details */}
        <div className="pt-3 space-y-2">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
            Entity Context
          </div>

          {node.nodeType === "employee" && (
            <div className="space-y-1.5 text-[11px]">
              {node.metadata.department && (
                <div className="flex justify-between py-1 border-b border-[var(--border)]">
                  <span className="text-[var(--text-secondary)]">Department:</span>
                  <span className="font-medium text-[var(--foreground)]">{node.metadata.department}</span>
                </div>
              )}
              <div className="flex justify-between py-1 border-b border-[var(--border)]">
                <span className="text-[var(--text-secondary)]">Connected Devices:</span>
                <span className="font-medium">{deviceEdges.length}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[var(--border)]">
                <span className="text-[var(--text-secondary)]">Connected IPs:</span>
                <span className="font-medium">{ipEdges.length}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[var(--border)]">
                <span className="text-[var(--text-secondary)]">Accessed Files:</span>
                <span className="font-medium">{fileEdges.length}</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-[var(--text-secondary)]">Generated Events:</span>
                <span className="font-medium">{eventEdges.length}</span>
              </div>
            </div>
          )}

          {node.nodeType === "event" && (
            <div className="space-y-1.5 text-[11px]">
              <div className="flex justify-between py-1 border-b border-[var(--border)]">
                <span className="text-[var(--text-secondary)]">Activity Type:</span>
                <span className="font-medium capitalize">{String(node.metadata.activity_type || "Login")}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[var(--border)]">
                <span className="text-[var(--text-secondary)]">Scenario:</span>
                <span className="font-medium">{String(node.metadata.scenario || "standard")}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[var(--border)]">
                <span className="text-[var(--text-secondary)]">Timestamp:</span>
                <span className="font-mono text-[10px]">{String(node.metadata.timestamp || "N/A")}</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-[var(--text-secondary)]">Event Risk Level:</span>
                <span className="font-semibold text-amber-700">{String(node.metadata.risk_level || "Low")}</span>
              </div>
            </div>
          )}

          {node.nodeType === "device" && (
            <div className="space-y-1.5 text-[11px]">
              <div className="flex justify-between py-1 border-b border-[var(--border)]">
                <span className="text-[var(--text-secondary)]">Distinct Users:</span>
                <span className="font-medium">{deviceEdges.length} employees</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[var(--border)]">
                <span className="text-[var(--text-secondary)]">Infrastructure Type:</span>
                <span className="font-medium">{isTrustedCorporate ? "Approved Shared Asset" : "Standard Workstation"}</span>
              </div>
              <div className="p-2 bg-[var(--surface-elevated)] border border-[var(--border)] rounded text-[10.5px] text-[var(--text-secondary)] mt-1">
                {deviceEdges.length > 1
                  ? `Device is used across ${deviceEdges.length} accounts. Multi-user correlation rules evaluated.`
                  : "Device is dedicated to a single employee profile."}
              </div>
            </div>
          )}

          {node.nodeType === "ip_address" && (
            <div className="space-y-1.5 text-[11px]">
              <div className="flex justify-between py-1 border-b border-[var(--border)]">
                <span className="text-[var(--text-secondary)]">Connected Accounts:</span>
                <span className="font-medium">{ipEdges.length} employees</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[var(--border)]">
                <span className="text-[var(--text-secondary)]">Network Status:</span>
                <span className="font-medium">{isTrustedCorporate ? "Trusted Corporate Gateway" : "External Endpoint"}</span>
              </div>
              <div className="p-2 bg-[var(--surface-elevated)] border border-[var(--border)] rounded text-[10.5px] text-[var(--text-secondary)] mt-1">
                {isTrustedCorporate
                  ? "Approved corporate VPN or NAT gateway; sharing does not trigger elevated security findings."
                  : ipEdges.length > 2
                  ? `External endpoint accessed by ${ipEdges.length} employees; analyzed for suspicious multi-account convergence.`
                  : "Standard single-user connection endpoint."}
              </div>
            </div>
          )}

          {node.nodeType === "file" && (
            <div className="space-y-1.5 text-[11px]">
              <div className="flex justify-between py-1 border-b border-[var(--border)]">
                <span className="text-[var(--text-secondary)]">Sensitivity:</span>
                <span className="font-bold text-amber-700">{String(node.metadata.sensitivity || "Restricted")}</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-[var(--text-secondary)]">Accessing Accounts:</span>
                <span className="font-medium">{fileEdges.length} employees</span>
              </div>
            </div>
          )}

          {node.nodeType === "attack_run" && (
            <div className="space-y-1.5 text-[11px]">
              <div className="flex justify-between py-1 border-b border-[var(--border)]">
                <span className="text-[var(--text-secondary)]">Scenario:</span>
                <span className="font-medium">{String(node.metadata.scenario || "Attack Lab Run")}</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-[var(--text-secondary)]">Linked Evidence:</span>
                <span className="font-medium">{attackEdges.length} connections</span>
              </div>
            </div>
          )}

          {/* Any remaining metadata */}
          {Object.entries(node.metadata).map(([key, value]) => {
            if (["department", "risk_level", "timestamp", "activity_type", "scenario", "sensitivity", "trusted"].includes(key)) {
              return null;
            }
            return (
              <div key={key} className="flex justify-between py-1 border-b border-[var(--border)] text-[11px]">
                <span className="text-[var(--text-secondary)] capitalize">{key.replace(/_/g, " ")}:</span>
                <span className="font-mono text-right text-[10px] break-all ml-2">{String(value)}</span>
              </div>
            );
          })}
        </div>

        {/* Section 3: Connected Security Findings */}
        <div className="pt-3 space-y-2">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)] flex items-center justify-between">
            <span>Security Findings</span>
            <span className="text-xs font-bold text-[var(--foreground)]">{associatedFindings.length}</span>
          </div>

          {associatedFindings.length === 0 ? (
            <div className="text-[11px] text-[var(--text-muted)] italic py-1">
              No correlated security findings for this entity.
            </div>
          ) : (
            <div className="space-y-2">
              {associatedFindings.map((f, i) => (
                <div
                  key={i}
                  className="p-2.5 rounded-md border border-[var(--border)] bg-[var(--surface-elevated)] space-y-1 text-[11px]"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-[var(--foreground)] capitalize">
                      {f.findingType.replace(/_/g, " ").toLowerCase()}
                    </span>
                    <span
                      className={`text-[9.5px] uppercase font-bold px-1.5 py-0.2 rounded ${
                        f.severity === "critical"
                          ? "bg-red-100 text-red-700"
                          : f.severity === "high"
                          ? "bg-orange-100 text-orange-700"
                          : f.severity === "medium"
                          ? "bg-amber-100 text-amber-700"
                          : "bg-blue-100 text-blue-700"
                      }`}
                    >
                      {f.severity}
                    </span>
                  </div>
                  <p className="text-[10.5px] text-[var(--text-secondary)] leading-relaxed">
                    {f.explanation}
                  </p>
                  {f.supportingEvents.length > 0 && (
                    <div className="text-[9.5px] text-[var(--text-muted)] pt-0.5">
                      Supporting Events: {f.supportingEvents.slice(0, 3).join(", ")}
                      {f.supportingEvents.length > 3 ? ` +${f.supportingEvents.length - 3} more` : ""}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Section 4: Direct Neighbors Quick Selection */}
        {neighborIds.length > 0 && onSelectRelatedNode && (
          <div className="pt-3 space-y-2">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
              Direct Neighbors ({neighborIds.length})
            </div>
            <div className="flex flex-wrap gap-1 max-h-36 overflow-y-auto">
              {neighborIds.slice(0, 20).map((nid) => (
                <button
                  key={nid}
                  type="button"
                  onClick={() => onSelectRelatedNode(nid)}
                  className="px-2 py-0.5 rounded border border-[var(--border)] bg-[var(--surface-elevated)] hover:bg-[var(--surface-hover)] hover:border-[var(--accent)] text-[10px] text-[var(--text-secondary)] transition-colors truncate max-w-[140px]"
                  title={nid}
                >
                  {nid}
                </button>
              ))}
              {neighborIds.length > 20 && (
                <span className="text-[10px] text-[var(--text-muted)] self-center px-1">
                  +{neighborIds.length - 20} more
                </span>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
