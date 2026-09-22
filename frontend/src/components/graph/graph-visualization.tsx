"use client";

import { useCallback, useEffect, useRef } from "react";
import * as echarts from "echarts/core";
import { GraphChart } from "echarts/charts";
import { LegendComponent, TooltipComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import type { GraphNode, GraphEdge } from "@/domain/sentinel";
import { NODE_CONFIGS, RISK_BORDER_CONFIGS, getNodeRiskLevel } from "./graph-types";

echarts.use([GraphChart, LegendComponent, TooltipComponent, CanvasRenderer]);

interface GraphVisualizationProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  selectedNode: GraphNode | null;
  onSelectNode: (node: GraphNode | null) => void;
  highlightedEntityIds?: string[];
  rearrangeEnabled?: boolean;
  showAllLabels?: boolean;
  chartRef?: React.MutableRefObject<echarts.ECharts | null>;
}

export function GraphVisualization({
  nodes,
  edges,
  selectedNode,
  onSelectNode,
  highlightedEntityIds = [],
  rearrangeEnabled = false,
  showAllLabels = false,
  chartRef,
}: GraphVisualizationProps) {
  const host = useRef<HTMLDivElement>(null);
  const chartInstance = useRef<echarts.ECharts | null>(null);

  const option = useCallback(() => {
    // 1. Transform Nodes with Category Fills and Separate Risk Borders
    const seriesData = nodes.map((n) => {
      const catConfig = NODE_CONFIGS[n.nodeType] || NODE_CONFIGS.employee;
      const riskLevel = getNodeRiskLevel(n) || "default";
      const riskBorder = RISK_BORDER_CONFIGS[riskLevel] || RISK_BORDER_CONFIGS.default;
      const isSelected = selectedNode?.nodeId === n.nodeId;
      const isHighlighted = highlightedEntityIds.includes(n.nodeId);

      // Intelligent label visibility: show for employees, attack runs, files, or selected
      const isImportantType = n.nodeType === "employee" || n.nodeType === "attack_run" || n.nodeType === "department";
      const shouldShowLabel = showAllLabels || isImportantType || isSelected || isHighlighted;

      return {
        id: n.nodeId,
        name: n.label,
        category: n.nodeType,
        symbol: catConfig.symbol,
        symbolSize: isSelected ? catConfig.symbolSize + 6 : isHighlighted ? catConfig.symbolSize + 4 : catConfig.symbolSize,
        draggable: rearrangeEnabled,
        // Entity type fill + separate risk indicator border
        itemStyle: {
          color: catConfig.fill,
          borderColor: isSelected ? "#10243e" : riskBorder.borderColor,
          borderWidth: isSelected ? 3.5 : riskBorder.borderWidth,
          borderType: "solid",
          shadowBlur: isSelected ? 12 : riskBorder.shadowColor ? 8 : 0,
          shadowColor: isSelected ? "rgba(37, 99, 235, 0.4)" : riskBorder.shadowColor || "transparent",
        },
        label: {
          show: shouldShowLabel,
          position: "right",
          formatter: "{b}",
          color: isSelected ? "#10243e" : "#475569",
          fontSize: isSelected ? 11 : 10,
          fontWeight: isSelected ? 600 : 400,
          distance: 5,
        },
        rawNode: n,
      };
    });

    // 2. Transform Edges with Muted Directional Styling and selective labels
    const seriesLinks = edges.map((e) => {
      const isConnectedToSelected = selectedNode && (e.sourceId === selectedNode.nodeId || e.targetId === selectedNode.nodeId);
      const isFindingEdge = highlightedEntityIds.includes(e.sourceId) && highlightedEntityIds.includes(e.targetId);

      return {
        source: e.sourceId,
        target: e.targetId,
        edgeType: e.edgeType,
        lineStyle: {
          color: isConnectedToSelected ? "#2563eb" : isFindingEdge ? "#ea580c" : "#94a3b8",
          width: isConnectedToSelected ? 2.5 : isFindingEdge ? 2.5 : 1.2,
          opacity: isConnectedToSelected ? 0.95 : isFindingEdge ? 0.9 : 0.45,
          curveness: 0.12,
        },
        label: {
          show: isConnectedToSelected || isFindingEdge || showAllLabels,
          formatter: e.edgeType,
          fontSize: 8.5,
          color: isConnectedToSelected ? "#1d4ed8" : isFindingEdge ? "#c2410c" : "#64748b",
          backgroundColor: "rgba(255, 255, 255, 0.85)",
          padding: [1, 3],
          borderRadius: 2,
        },
      };
    });

    return {
      backgroundColor: "transparent",
      animationDuration: 250,
      animationEasingUpdate: "cubicOut" as const,
      tooltip: {
        trigger: "item",
        backgroundColor: "#ffffff",
        borderColor: "#cbd5e1",
        borderWidth: 1,
        padding: [8, 12],
        extraCssText: "box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1); border-radius: 8px;",
        textStyle: { color: "#10243e", fontSize: 11 },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        formatter: (params: any) => {
          if (params.dataType === "node") {
            const raw = params.data.rawNode as GraphNode;
            const cat = NODE_CONFIGS[raw.nodeType]?.label || raw.nodeType;
            const risk = getNodeRiskLevel(raw);
            return `
              <div style="font-weight:600; font-size:12px; margin-bottom:4px;">${raw.label}</div>
              <div style="color:#64748b; font-size:10.5px;">Type: <span style="font-weight:500; color:#10243e;">${cat}</span></div>
              ${risk ? `<div style="color:#64748b; font-size:10.5px;">Risk Level: <span style="font-weight:600; color:${risk === "Critical" ? "#dc2626" : risk === "High" ? "#ea580c" : "#10b981"};">${risk}</span></div>` : ""}
              <div style="color:#94a3b8; font-size:9.5px; margin-top:4px;">Click to view security relationships</div>
            `;
          }
          if (params.dataType === "edge") {
            return `
              <div style="font-size:11px; font-weight:600; color:#10243e;">${params.data.edgeType}</div>
              <div style="font-size:10px; color:#64748b;">${params.data.source} → ${params.data.target}</div>
            `;
          }
          return "";
        },
      },
      series: [
        {
          type: "graph",
          layout: "force",
          roam: true,
          edgeSymbol: ["none", "arrow"],
          edgeSymbolSize: [0, 7],
          draggable: rearrangeEnabled,
          // CRITICAL: Stable layout without jitter
          force: {
            repulsion: 180,
            edgeLength: 75,
            friction: 0.9,
            gravity: 0.08,
            layoutAnimation: false, // Prevents node jumping on hover
          },
          // CRITICAL: scale: false prevents node enlargement that shifts force layout
          emphasis: {
            scale: false,
            focus: "adjacency",
            itemStyle: {
              borderWidth: 4,
              shadowBlur: 10,
              shadowColor: "rgba(0, 0, 0, 0.25)",
            },
            lineStyle: {
              width: 2.5,
              opacity: 0.95,
            },
          },
          blur: {
            itemStyle: {
              opacity: 0.2,
            },
            lineStyle: {
              opacity: 0.08,
            },
          },
          data: seriesData,
          links: seriesLinks,
        },
      ],
    };
  }, [nodes, edges, selectedNode, highlightedEntityIds, rearrangeEnabled, showAllLabels]);

  // Initialize and update ECharts
  useEffect(() => {
    if (!host.current) return;
    const chart = echarts.init(host.current, undefined, { renderer: "canvas" });
    chartInstance.current = chart;
    if (chartRef) chartRef.current = chart;

    chart.setOption(option());

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    chart.on("click", (params: any) => {
      if (params.dataType === "node" && params.data && params.data.rawNode) {
        onSelectNode(params.data.rawNode as GraphNode);
      }
    });

    // Deselect when clicking canvas background
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    chart.getZr().on("click", (event: any) => {
      if (!event.target) {
        onSelectNode(null);
      }
    });

    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(host.current);

    return () => {
      observer.disconnect();
      chart.dispose();
      chartInstance.current = null;
      if (chartRef) chartRef.current = null;
    };
  }, [option, onSelectNode, chartRef]);

  return (
    <div className="relative w-full h-[620px] bg-gradient-to-b from-white to-[var(--surface-hover)] border border-[var(--border)] rounded-lg overflow-hidden shadow-xs">
      {/* Canvas */}
      <div ref={host} role="img" aria-label="Entity Relationship Security Graph" className="w-full h-full" />

      {/* Graph Legend Overlay (Requirement 10) */}
      <div className="absolute bottom-3 left-3 z-10 bg-white/95 backdrop-blur-xs border border-[var(--border-strong)] rounded-lg p-3 shadow-md text-xs space-y-2.5 max-w-sm pointer-events-auto">
        {/* Category Legend */}
        <div>
          <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)] mb-1.5">
            Entity Categories
          </div>
          <div className="grid grid-cols-2 gap-x-3 gap-y-1.5">
            {Object.values(NODE_CONFIGS).map((cat) => (
              <div key={cat.name} className="flex items-center gap-1.5 text-[11px] text-[var(--text-secondary)]">
                <span
                  className="size-2.5 inline-block rounded-xs shrink-0"
                  style={{ backgroundColor: cat.fill }}
                />
                <span className="truncate">{cat.label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Risk Indicators Legend */}
        <div className="border-t border-[var(--border)] pt-2">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)] mb-1.5">
            Risk Ring Indicators
          </div>
          <div className="flex items-center gap-3 text-[10.5px]">
            <span className="flex items-center gap-1 text-emerald-700 font-medium">
              <span className="size-2 rounded-full border-2 border-emerald-500 bg-white inline-block" /> Low
            </span>
            <span className="flex items-center gap-1 text-amber-700 font-medium">
              <span className="size-2 rounded-full border-2 border-amber-500 bg-white inline-block" /> Med
            </span>
            <span className="flex items-center gap-1 text-orange-700 font-medium">
              <span className="size-2.5 rounded-full border-[2.5px] border-orange-500 bg-white inline-block" /> High
            </span>
            <span className="flex items-center gap-1 text-red-700 font-medium">
              <span className="size-3 rounded-full border-3 border-red-600 bg-white inline-block" /> Critical
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
