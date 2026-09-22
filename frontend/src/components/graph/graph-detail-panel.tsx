"use client";

import { X } from "lucide-react";
import type { GraphNode, GraphEdge } from "@/domain/sentinel";

interface GraphDetailPanelProps {
  node: GraphNode;
  edges: GraphEdge[];
  onClose: () => void;
}

export function GraphDetailPanel({ node, edges, onClose }: GraphDetailPanelProps) {
  // Calculate some basic stats from edges
  const connectedEdges = edges.filter(e => e.sourceId === node.nodeId || e.targetId === node.nodeId);
  const connectedDevices = connectedEdges.filter(e => e.edgeType === "USES_DEVICE").length;
  const connectedIps = connectedEdges.filter(e => e.edgeType === "CONNECTS_FROM" || e.edgeType === "LOGS_IN_FROM").length;
  const employeeUsers = connectedEdges.filter(e => e.edgeType === "USES_DEVICE" && e.sourceId.startsWith("employee:")).length;

  return (
    <div className="panel bg-[var(--surface)] p-4 border border-[var(--border)] rounded-lg">
      <div className="flex items-start justify-between mb-3">
        <div>
          <div className="tech-label mb-1">Entity Details</div>
          <h3 className="font-semibold text-sm break-all">{node.label}</h3>
        </div>
        <button onClick={onClose} className="text-[var(--text-muted)] hover:text-foreground">
          <X className="size-4" />
        </button>
      </div>

      <div className="space-y-3 text-xs">
        <div className="flex justify-between border-b border-[var(--border)] pb-2">
          <span className="text-[var(--text-secondary)]">Type</span>
          <span className="font-medium bg-[var(--surface-elevated)] px-1.5 py-0.5 rounded text-[10px]">
            {node.nodeType}
          </span>
        </div>

        {node.nodeType === "employee" && (
          <>
            {node.metadata.department && (
              <div className="flex justify-between border-b border-[var(--border)] pb-2">
                <span className="text-[var(--text-secondary)]">Department</span>
                <span>{node.metadata.department}</span>
              </div>
            )}
            <div className="flex justify-between border-b border-[var(--border)] pb-2">
              <span className="text-[var(--text-secondary)]">Connected Devices</span>
              <span>{connectedDevices}</span>
            </div>
            <div className="flex justify-between border-b border-[var(--border)] pb-2">
              <span className="text-[var(--text-secondary)]">Connected IPs</span>
              <span>{connectedIps}</span>
            </div>
          </>
        )}

        {node.nodeType === "device" && (
          <div className="flex justify-between border-b border-[var(--border)] pb-2">
            <span className="text-[var(--text-secondary)]">Used By Employees</span>
            <span>{employeeUsers}</span>
          </div>
        )}

        {Object.entries(node.metadata).map(([key, value]) => {
          if (key === "department" && node.nodeType === "employee") return null;
          return (
            <div key={key} className="flex justify-between border-b border-[var(--border)] pb-2">
              <span className="text-[var(--text-secondary)] capitalize">{key.replace(/_/g, " ")}</span>
              <span className="break-all text-right ml-2">{value}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
