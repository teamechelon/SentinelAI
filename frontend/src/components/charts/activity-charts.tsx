"use client";

import { useCallback, useEffect, useRef } from "react";
import * as echarts from "echarts/core";
import { BarChart, LineChart } from "echarts/charts";
import { GridComponent, LegendComponent, TooltipComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import type { AnomalyPoint, RiskPoint } from "@/domain/sentinel";

echarts.use([BarChart, LineChart, GridComponent, LegendComponent, TooltipComponent, CanvasRenderer]);

interface ChartColors { accent: string; critical: string; border: string; muted: string; secondary: string; surface: string; foreground: string; mono: string }

function readColors(): ChartColors {
  const styles = getComputedStyle(document.documentElement);
  const read = (token: string) => styles.getPropertyValue(token).trim();
  return { accent: read("--accent"), critical: read("--critical"), border: read("--border"), muted: read("--text-muted"), secondary: read("--text-secondary"), surface: read("--surface-elevated"), foreground: read("--foreground"), mono: read("--font-geist-mono") };
}

function base(colors: ChartColors): echarts.EChartsCoreOption {
  return {
    animation: false,
    backgroundColor: "transparent",
    textStyle: { color: colors.secondary, fontFamily: colors.mono, fontSize: 10 },
    grid: { left: 42, right: 22, top: 36, bottom: 34 },
    tooltip: { trigger: "axis", backgroundColor: colors.surface, borderColor: colors.border, textStyle: { color: colors.foreground, fontSize: 11 } },
    legend: { top: 0, right: 0, textStyle: { color: colors.muted, fontSize: 10 }, itemWidth: 12, itemHeight: 2 },
  };
}

function Chart({ createOption, label }: { createOption: (colors: ChartColors) => echarts.EChartsCoreOption; label: string }) {
  const host = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!host.current) return;
    const chart = echarts.init(host.current, undefined, { renderer: "canvas" });
    chart.setOption(createOption(readColors()));
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(host.current);
    return () => { observer.disconnect(); chart.dispose(); };
  }, [createOption]);
  return <div ref={host} role="img" aria-label={label} className="h-[220px] w-full" />;
}

function DataTable({ headers, rows, label }: { headers: string[]; rows: (string | number)[][]; label: string }) {
  return (
    <details className="mt-2 border-t border-border pt-2 text-[10px] text-[var(--text-muted)]">
      <summary className="w-fit cursor-pointer rounded-sm py-1 hover:text-foreground">View source data</summary>
      <div className="scrollbar-thin mt-2 max-h-52 overflow-auto border border-border">
        <table className="w-full min-w-[360px] border-collapse font-mono"><caption className="sr-only">{label}</caption><thead className="sticky top-0 bg-[var(--surface-elevated)]"><tr>{headers.map((header) => <th key={header} scope="col" className="border-b border-border px-2 py-1.5 text-left font-semibold text-[var(--text-secondary)]">{header}</th>)}</tr></thead><tbody className="divide-y divide-border">{rows.map((row) => <tr key={String(row[0])}>{row.map((value, index) => <td key={`${row[0]}-${headers[index]}`} className="px-2 py-1.5 tabular">{value}</td>)}</tr>)}</tbody></table>
      </div>
    </details>
  );
}

export function RiskActivityChart({ points }: { points: RiskPoint[] }) {
  const createOption = useCallback((colors: ChartColors): echarts.EChartsCoreOption => ({
    ...base(colors),
    xAxis: { type: "category", data: points.map((p) => p.date.slice(5)), axisLabel: { color: colors.muted, interval: 9 }, axisLine: { lineStyle: { color: colors.border } }, axisTick: { show: false } },
    yAxis: [
      { type: "value", name: "Risk", min: 0, max: 100, nameTextStyle: { color: colors.muted }, axisLabel: { color: colors.muted }, splitLine: { lineStyle: { color: colors.border } } },
      { type: "value", name: "Alerts", min: 0, nameTextStyle: { color: colors.muted }, axisLabel: { color: colors.muted }, splitLine: { show: false } },
    ],
    series: [
      { name: "Average risk", type: "line", data: points.map((p) => p.averageRisk), symbol: "none", lineStyle: { width: 2, color: colors.accent }, itemStyle: { color: colors.accent } },
      { name: "Alerts", type: "bar", yAxisIndex: 1, data: points.map((p) => p.alertCount), barMaxWidth: 7, itemStyle: { color: colors.critical, opacity: 0.55 } },
    ],
  }), [points]);
  return <><Chart label="Daily average persisted risk score and alert count" createOption={createOption} /><DataTable label="Risk activity source data" headers={["Date", "Average risk", "Alerts"]} rows={points.map((point) => [point.date, point.averageRisk.toFixed(2), point.alertCount])} /></>;
}

export function AnomalyActivityChart({ points }: { points: AnomalyPoint[] }) {
  const createOption = useCallback((colors: ChartColors): echarts.EChartsCoreOption => ({
    ...base(colors),
    xAxis: { type: "category", data: points.map((p) => p.date.slice(5)), axisLabel: { color: colors.muted, interval: 9 }, axisLine: { lineStyle: { color: colors.border } }, axisTick: { show: false } },
    yAxis: { type: "value", name: "Percentile", min: 0, max: 100, nameTextStyle: { color: colors.muted }, axisLabel: { color: colors.muted }, splitLine: { lineStyle: { color: colors.border } } },
    series: [
      { name: "P95", type: "line", data: points.map((p) => p.p95Percentile), symbol: "none", lineStyle: { width: 1, color: colors.secondary, type: "dashed" }, itemStyle: { color: colors.secondary } },
      { name: "Median", type: "line", data: points.map((p) => p.medianPercentile), symbol: "none", lineStyle: { width: 2, color: colors.accent }, itemStyle: { color: colors.accent } },
    ],
  }), [points]);
  return <><Chart label="Daily persisted anomaly percentile median and 95th percentile" createOption={createOption} /><DataTable label="Anomaly activity source data" headers={["Date", "Median percentile", "P95 percentile"]} rows={points.map((point) => [point.date, point.medianPercentile.toFixed(2), point.p95Percentile.toFixed(2)])} /></>;
}
