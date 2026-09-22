import type { GraphNode } from "@/domain/sentinel";

export interface NodeCategoryConfig {
  name: string;
  label: string;
  fill: string;
  border: string;
  text: string;
  bg: string;
  symbol: string;
  symbolSize: number;
}

export const NODE_CONFIGS: Record<string, NodeCategoryConfig> = {
  employee: {
    name: "employee",
    label: "Employee",
    fill: "#2563eb", // Professional Blue
    border: "#1d4ed8",
    text: "#1d4ed8",
    bg: "#eff6ff",
    symbol: "circle",
    symbolSize: 26,
  },
  event: {
    name: "event",
    label: "Security Event",
    fill: "#7c3aed", // Indigo / Violet
    border: "#6d28d9",
    text: "#6d28d9",
    bg: "#f5f3ff",
    symbol: "diamond",
    symbolSize: 18,
  },
  device: {
    name: "device",
    label: "Device",
    fill: "#0d9488", // Teal
    border: "#0f766e",
    text: "#0f766e",
    bg: "#f0fdfa",
    symbol: "roundRect",
    symbolSize: 24,
  },
  ip_address: {
    name: "ip_address",
    label: "IP Address",
    fill: "#0284c7", // Sky / Cyan
    border: "#0369a1",
    text: "#0369a1",
    bg: "#f0f9ff",
    symbol: "triangle",
    symbolSize: 22,
  },
  location: {
    name: "location",
    label: "Location",
    fill: "#059669", // Emerald Green
    border: "#047857",
    text: "#047857",
    bg: "#ecfdf5",
    symbol: "pin",
    symbolSize: 24,
  },
  file: {
    name: "file",
    label: "File",
    fill: "#d97706", // Amber / Gold
    border: "#b45309",
    text: "#b45309",
    bg: "#fffbeb",
    symbol: "rect",
    symbolSize: 22,
  },
  department: {
    name: "department",
    label: "Department",
    fill: "#9333ea", // Purple
    border: "#7e22ce",
    text: "#7e22ce",
    bg: "#faf5ff",
    symbol: "circle",
    symbolSize: 28,
  },
  attack_run: {
    name: "attack_run",
    label: "Attack Lab Run",
    fill: "#e11d48", // Coral / Crimson
    border: "#be123c",
    text: "#be123c",
    bg: "#fff1f2",
    symbol: "diamond",
    symbolSize: 32,
  },
};

export const RISK_BORDER_CONFIGS: Record<string, { borderColor: string; borderWidth: number; shadowColor?: string }> = {
  Low: {
    borderColor: "#10b981",
    borderWidth: 2,
  },
  Medium: {
    borderColor: "#f59e0b",
    borderWidth: 2.5,
  },
  High: {
    borderColor: "#ea580c",
    borderWidth: 3.5,
    shadowColor: "rgba(234, 88, 12, 0.4)",
  },
  Critical: {
    borderColor: "#dc2626",
    borderWidth: 4.5,
    shadowColor: "rgba(220, 38, 38, 0.6)",
  },
  default: {
    borderColor: "#ffffff",
    borderWidth: 1.5,
  },
};

export function getNodeRiskLevel(node: GraphNode): string | null {
  if (node.nodeType === "event") {
    return (node.metadata.risk_level as string) || "Low";
  }
  if (node.nodeType === "attack_run") {
    return "High";
  }
  if (node.metadata.sensitivity === "Restricted" || node.metadata.sensitivity === "Confidential") {
    return "High";
  }
  return null;
}
