"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import * as echarts from "echarts/core";
import { GraphChart } from "echarts/charts";
import { LegendComponent, TooltipComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import type { GraphNode, GraphEdge } from "@/domain/sentinel";
import { GraphDetailPanel } from "./graph-detail-panel";

echarts.use([GraphChart, LegendComponent, TooltipComponent, CanvasRenderer]);

interface Colors {
  accent: string;
  low: string;
  medium: string;
  high: string;
  critical: string;
  border: string;
  muted: string;
  secondary: string;
  surface: string;
  foreground: string;
}

function getColors(): Colors {
  if (typeof document === "undefined") return {} as Colors;
  const style = getComputedStyle(document.documentElement);
  const read = (name: string) => style.getPropertyValue(name).trim();
  return {
    accent: read("--accent"),
    low: read("--low"),
    medium: read("--medium"),
    high: read("--high"),
    critical: read("--critical"),
    border: read("--border"),
    muted: read("--text-muted"),
    secondary: read("--text-secondary"),
    surface: read("--surface"),
    foreground: read("--foreground"),
  };
}

const TYPE_COLORS: Record<string, string> = {
  employee: "var(--accent)",
  event: "#ec4899",
  device: "#8b5cf6",
  ip_address: "#06b6d4",
  location: "#f59e0b",
  file: "#10b981",
  department: "#6b7280",
  attack_run: "var(--critical)",
};

interface GraphVisualizationProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export function GraphVisualization({ nodes, edges }: GraphVisualizationProps) {
  const host = useRef<HTMLDivElement>(null);
  const chartInstance = useRef<echarts.ECharts | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  const option = useCallback((palette: Colors) => {
    // Categories for legend
    const categories = [
      { name: "employee" },
      { name: "event" },
      { name: "device" },
      { name: "ip_address" },
      { name: "location" },
      { name: "file" },
      { name: "department" },
      { name: "attack_run" },
    ];


    return {
      animationDuration: 300,
      tooltip: {
        backgroundColor: palette.surface,
        borderColor: palette.border,
        borderWidth: 1,
        textStyle: { color: palette.foreground, fontSize: 11 },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        formatter: (params: any) => {
          if (params.dataType === "node") {
            return `<strong>${params.data.label}</strong><br/>Type: ${params.data.category}`;
          }
          if (params.dataType === "edge") {
            return `<strong>${params.data.edgeType}</strong>`;
          }
          return "";
        }
      },
      legend: {
        data: categories.map(c => c.name),
        textStyle: { color: palette.secondary, fontSize: 10 },
        bottom: 0,
      },
      series: [
        {
          type: "graph",
          layout: "force",
          roam: true,
          label: {
            show: true,
            position: "right",
            formatter: "{b}",
            color: palette.secondary,
            fontSize: 10
          },
          force: {
            repulsion: 150,
            edgeLength: 50,
          },
          data: nodes.map(n => ({
            id: n.nodeId,
            name: n.label,
            category: n.nodeType,
            symbolSize: n.nodeType === "employee" ? 30 : 20,
            itemStyle: {
              color: TYPE_COLORS[n.nodeType] || palette.accent,
            },
            ...n
          })),
          links: edges.map(e => ({
            source: e.sourceId,
            target: e.targetId,
            edgeType: e.edgeType,
            label: {
              show: true,
              formatter: e.edgeType,
              fontSize: 9,
              color: palette.muted,
            }
          })),
          categories: categories,
          lineStyle: {
            color: palette.border,
            curveness: 0.1,
          },
          emphasis: {
            focus: "adjacency",
            lineStyle: {
              width: 2,
            }
          }
        }
      ]
    };
  }, [nodes, edges]);

  useEffect(() => {
    if (!host.current) return;
    const chart = echarts.init(host.current, undefined, { renderer: "canvas" });
    chartInstance.current = chart;
    
    chart.setOption(option(getColors()));
    
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    chart.on("click", (params: any) => {
      if (params.dataType === "node" && params.data && params.data.id) {
        const node = nodes.find(n => n.nodeId === params.data.id);
        if (node) setSelectedNode(node);
      } else {
        setSelectedNode(null);
      }
    });

    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(host.current);
    
    return () => { 
      observer.disconnect(); 
      chart.dispose(); 
    };
  }, [option, nodes]);

  return (
    <div className="relative">
      <div ref={host} role="img" aria-label="Entity Relationship Graph" style={{ height: 500 }} className="w-full" />
      {selectedNode && (
        <div className="absolute top-4 right-4 z-10 w-80 shadow-lg">
          <GraphDetailPanel node={selectedNode} onClose={() => setSelectedNode(null)} edges={edges} />
        </div>
      )}
    </div>
  );
}
