"use client";

import { useCallback, useEffect, useRef } from "react";
import * as echarts from "echarts/core";
import { BarChart, LineChart, PieChart } from "echarts/charts";
import { GridComponent, LegendComponent, TooltipComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import type { UserDetail } from "@/domain/sentinel";

echarts.use([BarChart, LineChart, PieChart, GridComponent, LegendComponent, TooltipComponent, CanvasRenderer]);

function BehaviourChart({ label, option }: { label: string; option: (colors: Record<string, string>) => echarts.EChartsCoreOption }) {
  const host = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!host.current) return;
    const style = getComputedStyle(document.documentElement);
    const read = (name: string) => style.getPropertyValue(name).trim();
    const chart = echarts.init(host.current);
    chart.setOption(option({ accent: read("--accent"), low: read("--low"), medium: read("--medium"), critical: read("--critical"), border: read("--border"), muted: read("--text-muted"), secondary: read("--text-secondary"), foreground: read("--foreground"), surface: read("--surface") }));
    const observer = new ResizeObserver(() => chart.resize()); observer.observe(host.current);
    return () => { observer.disconnect(); chart.dispose(); };
  }, [option]);
  return <div ref={host} role="img" aria-label={label} className="h-[210px] w-full" />;
}

function VisualCard({ title, description, children }: { title: string; description: string; children: React.ReactNode }) {
  return <article className="panel p-5"><h3 className="text-[13px] font-bold">{title}</h3><p className="mt-1 text-[9px] leading-4 text-[var(--text-muted)]">{description}</p><div className="mt-2">{children}</div></article>;
}

export function UserBehaviourVisuals({ user }: { user: UserDetail }) {
  const risk = [...user.riskHistory].sort((a, b) => a.occurredAt.localeCompare(b.occurredAt));
  const loginHours = Array.from({ length: 24 }, (_, hour) => ({ hour, count: 0 }));
  const locations = new Map<string, number>();
  let known = 0; let unknown = 0; let observedDownload = 0; let downloadEvents = 0;
  for (const event of user.activityHistory) {
    if (event.activityType === "login") loginHours[new Date(event.occurredAt).getUTCHours()].count += 1;
    locations.set(`${event.city}, ${event.country}`, (locations.get(`${event.city}, ${event.country}`) ?? 0) + 1);
    if (event.isKnownDevice) known += 1; else unknown += 1;
    if (event.activityType === "download") { observedDownload += event.downloadSizeMb; downloadEvents += 1; }
  }
  const locationRows = [...locations].sort((a, b) => b[1] - a[1]).slice(0, 6).reverse();
  const commonTooltip = (c: Record<string, string>) => ({ trigger: "axis" as const, backgroundColor: c.surface, borderColor: c.border, textStyle: { color: c.foreground, fontSize: 10 } });
  const riskOption = useCallback((c: Record<string, string>): echarts.EChartsCoreOption => ({ animationDuration: 200, grid: { left: 34, right: 12, top: 16, bottom: 26 }, tooltip: commonTooltip(c), xAxis: { type: "category", data: risk.map((item) => item.occurredAt.slice(5, 10)), axisLine: { show: false }, axisTick: { show: false }, axisLabel: { color: c.muted, fontSize: 9, interval: Math.max(0, Math.floor(risk.length / 5)) } }, yAxis: { type: "value", min: 0, max: 100, axisLine: { show: false }, axisLabel: { color: c.muted, fontSize: 9 }, splitLine: { lineStyle: { color: c.border, type: "dashed" } } }, series: [{ name: "Risk", type: "line", smooth: .3, showSymbol: false, data: risk.map((item) => item.riskScore), lineStyle: { color: c.accent, width: 2.5 }, areaStyle: { color: "rgba(37,99,235,.10)" } }] }), [risk]);
  const loginOption = useCallback((c: Record<string, string>): echarts.EChartsCoreOption => ({ animationDuration: 200, grid: { left: 30, right: 10, top: 16, bottom: 26 }, tooltip: commonTooltip(c), xAxis: { type: "category", data: loginHours.map((item) => String(item.hour).padStart(2, "0")), axisLine: { show: false }, axisTick: { show: false }, axisLabel: { color: c.muted, fontSize: 9, interval: 3 } }, yAxis: { type: "value", minInterval: 1, axisLine: { show: false }, axisLabel: { color: c.muted, fontSize: 9 }, splitLine: { lineStyle: { color: c.border, type: "dashed" } } }, series: [{ name: "Logins", type: "bar", data: loginHours.map((item) => item.count), barWidth: 7, itemStyle: { color: c.accent, borderRadius: [4, 4, 0, 0] } }] }), [loginHours]);
  const deviceOption = useCallback((c: Record<string, string>): echarts.EChartsCoreOption => ({ animationDuration: 200, tooltip: { trigger: "item", backgroundColor: c.surface, borderColor: c.border, textStyle: { color: c.foreground, fontSize: 10 } }, legend: { bottom: 0, icon: "circle", textStyle: { color: c.secondary, fontSize: 9 } }, series: [{ type: "pie", radius: ["52%", "74%"], center: ["50%", "43%"], label: { show: false }, itemStyle: { borderColor: c.surface, borderWidth: 3 }, data: [{ name: "Known device", value: known, itemStyle: { color: c.low } }, { name: "Unknown device", value: unknown, itemStyle: { color: c.critical } }] }] }), [known, unknown]);
  const locationOption = useCallback((c: Record<string, string>): echarts.EChartsCoreOption => ({ animationDuration: 200, grid: { left: 102, right: 12, top: 10, bottom: 22 }, tooltip: commonTooltip(c), xAxis: { type: "value", minInterval: 1, axisLine: { show: false }, axisLabel: { color: c.muted, fontSize: 9 }, splitLine: { lineStyle: { color: c.border, type: "dashed" } } }, yAxis: { type: "category", data: locationRows.map(([name]) => name), axisLine: { show: false }, axisTick: { show: false }, axisLabel: { color: c.secondary, fontSize: 9 } }, series: [{ type: "bar", data: locationRows.map(([, count]) => count), barWidth: 9, itemStyle: { color: c.accent, borderRadius: [0, 5, 5, 0] } }] }), [locationRows]);
  const observedAverage = downloadEvents ? observedDownload / downloadEvents : 0;
  const downloadOption = useCallback((c: Record<string, string>): echarts.EChartsCoreOption => ({ animationDuration: 200, grid: { left: 40, right: 12, top: 30, bottom: 28 }, tooltip: commonTooltip(c), legend: { top: 0, icon: "circle", itemWidth: 7, itemHeight: 7, textStyle: { color: c.secondary, fontSize: 9 } }, xAxis: { type: "category", data: ["Download size"], axisLine: { show: false }, axisTick: { show: false }, axisLabel: { color: c.secondary, fontSize: 9 } }, yAxis: { type: "value", axisLine: { show: false }, axisLabel: { color: c.muted, fontSize: 9, formatter: "{value} MB" }, splitLine: { lineStyle: { color: c.border, type: "dashed" } } }, series: [{ name: "Normal behaviour", type: "bar", data: [user.personalBaseline.averageDownloadSizeMb], barWidth: 28, itemStyle: { color: c.low, borderRadius: [6, 6, 0, 0] } }, { name: "Observed behaviour", type: "bar", data: [Number(observedAverage.toFixed(2))], barWidth: 28, itemStyle: { color: c.accent, borderRadius: [6, 6, 0, 0] } }] }), [observedAverage, user.personalBaseline.averageDownloadSizeMb]);
  return <div className="grid gap-4 xl:grid-cols-2"><VisualCard title="Risk History" description="Persisted final risk score across recent detections"><BehaviourChart label="Risk history" option={riskOption} /></VisualCard><VisualCard title="Login Activity Pattern" description="Observed login distribution by hour of day (UTC)"><BehaviourChart label="Login activity by hour" option={loginOption} /></VisualCard><VisualCard title="Device Usage" description="Known and unknown device activity in recent observations"><BehaviourChart label="Known versus unknown device usage" option={deviceOption} /></VisualCard><VisualCard title="Location Behaviour" description="Most frequently observed recent locations"><BehaviourChart label="Recent activity by location" option={locationOption} /></VisualCard><div className="xl:col-span-2"><VisualCard title="Download Behaviour" description="Normal baseline compared with the average observed download size"><BehaviourChart label="Normal and observed download behaviour" option={downloadOption} /></VisualCard></div></div>;
}
