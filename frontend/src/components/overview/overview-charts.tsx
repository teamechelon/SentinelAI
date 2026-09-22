"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import * as echarts from "echarts/core";
import { BarChart, LineChart, PieChart } from "echarts/charts";
import { GraphicComponent, GridComponent, LegendComponent, TooltipComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import type { DetectionContribution, NamedMetric, RiskLevel, RiskPoint, ThreatTrendPoint } from "@/domain/sentinel";

echarts.use([BarChart, LineChart, PieChart, GraphicComponent, GridComponent, LegendComponent, TooltipComponent, CanvasRenderer]);

type ChartClick = { name?: string };
interface Colors { accent: string; low: string; medium: string; high: string; critical: string; border: string; muted: string; secondary: string; surface: string; foreground: string }

function colors(): Colors {
  const style = getComputedStyle(document.documentElement);
  const read = (name: string) => style.getPropertyValue(name).trim();
  return { accent: read("--accent"), low: read("--low"), medium: read("--medium"), high: read("--high"), critical: read("--critical"), border: read("--border"), muted: read("--text-muted"), secondary: read("--text-secondary"), surface: read("--surface"), foreground: read("--foreground") };
}

function Chart({ option, label, height = 270, onClick }: { option: (palette: Colors) => echarts.EChartsCoreOption; label: string; height?: number; onClick?: (event: ChartClick) => void }) {
  const host = useRef<HTMLDivElement>(null);
  const clickRef = useRef(onClick);
  useEffect(() => { clickRef.current = onClick; }, [onClick]);
  useEffect(() => {
    if (!host.current) return;
    const chart = echarts.init(host.current, undefined, { renderer: "canvas" });
    chart.setOption(option(colors()));
    chart.on("click", (event) => clickRef.current?.(event));
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(host.current);
    return () => { observer.disconnect(); chart.dispose(); };
  }, [option]);
  return <div ref={host} role="img" aria-label={label} style={{ height }} className="w-full" />;
}

const axis = (palette: Colors) => ({ axisLine: { show: false }, axisTick: { show: false }, axisLabel: { color: palette.muted, fontSize: 10 }, splitLine: { lineStyle: { color: palette.border, type: "dashed" as const } } });
const tooltip = (palette: Colors) => ({ trigger: "axis" as const, backgroundColor: palette.surface, borderColor: palette.border, borderWidth: 1, padding: 12, textStyle: { color: palette.foreground, fontSize: 11 }, extraCssText: "box-shadow:0 10px 28px rgba(15,35,59,.12);border-radius:10px" });

export function ThreatTrendChart({ points }: { points: ThreatTrendPoint[] }) {
  const [period, setPeriod] = useState<7 | 30 | 90>(30);
  const visible = useMemo(() => points.slice(-period), [period, points]);
  const option = useCallback((palette: Colors): echarts.EChartsCoreOption => ({
    animationDuration: 220,
    grid: { left: 34, right: 14, top: 38, bottom: 30 },
    tooltip: { ...tooltip(palette), valueFormatter: (value: unknown) => `${value} detected events` },
    legend: { top: 0, right: 0, icon: "circle", itemWidth: 7, itemHeight: 7, textStyle: { color: palette.secondary, fontSize: 10 } },
    xAxis: { type: "category", boundaryGap: false, data: visible.map((item) => item.date.slice(5)), ...axis(palette), splitLine: { show: false }, axisLabel: { color: palette.muted, fontSize: 10, interval: Math.max(0, Math.floor(visible.length / 6) - 1) } },
    yAxis: { type: "value", minInterval: 1, ...axis(palette) },
    series: [
      { name: "Medium", type: "line", smooth: 0.25, symbol: "none", data: visible.map((item) => item.medium), lineStyle: { color: palette.medium, width: 2 }, areaStyle: { color: "rgba(217,154,22,.07)" }, itemStyle: { color: palette.medium } },
      { name: "High", type: "line", smooth: 0.25, symbol: "none", data: visible.map((item) => item.high), lineStyle: { color: palette.high, width: 2 }, itemStyle: { color: palette.high } },
      { name: "Critical", type: "line", smooth: 0.25, symbol: "none", data: visible.map((item) => item.critical), lineStyle: { color: palette.critical, width: 2 }, itemStyle: { color: palette.critical } },
    ],
  }), [visible]);
  return <div><div className="mb-1 flex justify-end gap-1">{([7, 30, 90] as const).map((value) => <button key={value} onClick={() => setPeriod(value)} className={`rounded-md px-2.5 py-1 text-[10px] font-semibold transition-colors ${period === value ? "bg-[var(--accent)] text-white" : "bg-[var(--surface-elevated)] text-[var(--text-muted)] hover:text-foreground"}`}>{value === 90 ? "All" : `${value} Days`}</button>)}</div><Chart option={option} label={`Threat activity trend for ${period === 90 ? "all available days" : `${period} days`}`} /></div>;
}

export function RiskDistributionChart({ distribution }: { distribution: Record<RiskLevel, number> }) {
  const router = useRouter();
  const total = Object.values(distribution).reduce((sum, value) => sum + value, 0);
  const option = useCallback((palette: Colors): echarts.EChartsCoreOption => ({
    animationDuration: 220,
    tooltip: { trigger: "item", backgroundColor: palette.surface, borderColor: palette.border, borderWidth: 1, textStyle: { color: palette.foreground, fontSize: 11 }, formatter: (value: { name: string; value: number; percent: number }) => `<strong>${value.name} risk</strong><br/>${value.value} events · ${value.percent}%` },
    legend: { bottom: 0, icon: "circle", itemWidth: 7, itemHeight: 7, textStyle: { color: palette.secondary, fontSize: 10 } },
    graphic: [{ type: "text", left: "center", top: "39%", style: { text: `${total.toLocaleString()}\nEvents`, textAlign: "center", fill: palette.foreground, fontSize: 18, fontWeight: 700, lineHeight: 24 } }],
    series: [{ type: "pie", radius: ["58%", "78%"], center: ["50%", "43%"], avoidLabelOverlap: true, label: { show: false }, emphasis: { scaleSize: 5 }, itemStyle: { borderColor: palette.surface, borderWidth: 3, borderRadius: 4 }, data: [
      { name: "Low", value: distribution.Low, itemStyle: { color: palette.low } },
      { name: "Medium", value: distribution.Medium, itemStyle: { color: palette.medium } },
      { name: "High", value: distribution.High, itemStyle: { color: palette.high } },
      { name: "Critical", value: distribution.Critical, itemStyle: { color: palette.critical } },
    ] }],
  }), [distribution, total]);
  return <Chart option={option} label="Risk distribution. Select a segment to open filtered activity." onClick={(event) => event.name && router.push(`/activity?riskLevel=${encodeURIComponent(event.name)}`)} />;
}

export function ThreatTypesChart({ items }: { items: NamedMetric[] }) {
  const router = useRouter();
  const shown = items.slice(0, 7).reverse();
  const option = useCallback((palette: Colors): echarts.EChartsCoreOption => ({
    animationDuration: 220,
    grid: { left: 122, right: 22, top: 8, bottom: 22 },
    tooltip: { ...tooltip(palette), trigger: "item", formatter: (value: { name: string; value: number }) => `<strong>${value.name}</strong><br/>${value.value} triggered detections` },
    xAxis: { type: "value", minInterval: 1, ...axis(palette) },
    yAxis: { type: "category", data: shown.map((item) => item.name), ...axis(palette), splitLine: { show: false }, axisLabel: { color: palette.secondary, fontSize: 10 } },
    series: [{ type: "bar", data: shown.map((item) => item.count), barWidth: 11, itemStyle: { color: palette.accent, borderRadius: [0, 6, 6, 0] }, emphasis: { itemStyle: { color: "#1d4ed8" } } }],
  }), [shown]);
  return <Chart option={option} label="Triggered detections by rule type. Select a bar to investigate matching alerts." onClick={(event) => event.name && router.push(`/threats?q=${encodeURIComponent(event.name.replaceAll(" ", "_"))}`)} />;
}

export function AverageRiskChart({ points }: { points: RiskPoint[] }) {
  const visible = points.slice(-30);
  const option = useCallback((palette: Colors): echarts.EChartsCoreOption => ({
    animationDuration: 220,
    grid: { left: 36, right: 16, top: 18, bottom: 30 }, tooltip: { ...tooltip(palette), valueFormatter: (value: unknown) => `${Number(value).toFixed(1)} / 100` },
    xAxis: { type: "category", boundaryGap: false, data: visible.map((item) => item.date.slice(5)), ...axis(palette), splitLine: { show: false }, axisLabel: { color: palette.muted, fontSize: 10, interval: 5 } },
    yAxis: { type: "value", min: 0, max: 100, ...axis(palette) },
    series: [{ name: "Average risk", type: "line", smooth: 0.35, symbol: "circle", symbolSize: 4, showSymbol: false, data: visible.map((item) => item.averageRisk), lineStyle: { color: palette.accent, width: 2.5 }, itemStyle: { color: palette.accent }, areaStyle: { color: "rgba(37,99,235,.10)" } }],
  }), [visible]);
  return <Chart option={option} label="Average risk score over the most recent 30 days" height={245} />;
}

export function DetectionContributionChart({ contribution }: { contribution: DetectionContribution }) {
  const option = useCallback((palette: Colors): echarts.EChartsCoreOption => ({
    animationDuration: 220,
    grid: { left: 12, right: 12, top: 70, bottom: 42 },
    tooltip: { trigger: "item", backgroundColor: palette.surface, borderColor: palette.border, borderWidth: 1, textStyle: { color: palette.foreground, fontSize: 11 }, valueFormatter: (value: unknown) => `${Number(value).toFixed(1)}% of aggregate score contribution` },
    legend: { bottom: 0, icon: "circle", itemWidth: 7, itemHeight: 7, textStyle: { color: palette.secondary, fontSize: 10 } },
    xAxis: { type: "value", max: 100, show: false }, yAxis: { type: "category", data: ["Detection mix"], show: false },
    series: [
      { name: "Explainable rules", type: "bar", stack: "mix", data: [contribution.ruleBased], barWidth: 28, itemStyle: { color: palette.accent, borderRadius: [8, 0, 0, 8] } },
      { name: "AI anomaly", type: "bar", stack: "mix", data: [contribution.aiAnomaly], barWidth: 28, itemStyle: { color: "#7c6fe8" } },
      { name: "Contextual severity", type: "bar", stack: "mix", data: [contribution.contextual], barWidth: 28, itemStyle: { color: palette.medium, borderRadius: [0, 8, 8, 0] } },
    ],
  }), [contribution]);
  return <Chart option={option} label="Aggregate contribution of rules, AI anomaly detection, and contextual severity" height={215} />;
}

export function DepartmentRiskChart({ items }: { items: NamedMetric[] }) {
  const router = useRouter();
  const shown = [...items].slice(0, 7).reverse();
  const option = useCallback((palette: Colors): echarts.EChartsCoreOption => ({
    animationDuration: 220,
    grid: { left: 92, right: 24, top: 8, bottom: 24 },
    tooltip: { ...tooltip(palette), trigger: "item", formatter: (value: { name: string; value: number; dataIndex: number }) => { const item = shown[value.dataIndex]; return `<strong>${value.name}</strong><br/>Average risk ${value.value.toFixed(1)} / 100<br/>${item.highCriticalCount ?? 0} High or Critical events`; } },
    xAxis: { type: "value", min: 0, max: 100, ...axis(palette) },
    yAxis: { type: "category", data: shown.map((item) => item.name), ...axis(palette), splitLine: { show: false }, axisLabel: { color: palette.secondary, fontSize: 10 } },
    series: [{ type: "bar", data: shown.map((item) => item.averageRisk ?? 0), barWidth: 12, itemStyle: { color: palette.accent, borderRadius: [0, 6, 6, 0] } }],
  }), [shown]);
  return <Chart option={option} label="Average risk score by department. Select a bar to open filtered activity." onClick={(event) => event.name && router.push(`/activity?department=${encodeURIComponent(event.name)}`)} />;
}
