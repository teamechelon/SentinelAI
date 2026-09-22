import Link from "next/link";
import { Activity, ArrowRight, BrainCircuit, CircleAlert, Database, Info, ShieldCheck, Siren, Sparkles, TrendingUp, UsersRound } from "lucide-react";
import { AverageRiskChart, DepartmentRiskChart, DetectionContributionChart, RiskDistributionChart, ThreatTrendChart, ThreatTypesChart } from "@/components/overview/overview-charts";
import { getSentinelDataSource } from "@/data/data-source";
import type { EmployeeAttention, NamedMetric, RiskLevel, ThreatSummary, ThreatTrendPoint, UserSummary } from "@/domain/sentinel";

const riskColor: Record<RiskLevel, string> = { Low: "var(--low)", Medium: "var(--medium)", High: "var(--high)", Critical: "var(--critical)" };

function posture(score: number) {
  if (score < 25) return { label: "Low Risk", color: "var(--low)", message: "Current activity remains within a generally controlled risk range." };
  if (score < 45) return { label: "Moderate Risk", color: "var(--medium)", message: "Elevated behaviours are present and should be reviewed." };
  if (score < 70) return { label: "High Risk", color: "var(--high)", message: "Material behavioural anomalies require active investigation." };
  return { label: "Critical Risk", color: "var(--critical)", message: "The monitored environment requires immediate analyst attention." };
}

function titleCase(value: string) { return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase()); }

function fallbackThreatTypes(threats: ThreatSummary[]): NamedMetric[] {
  const counts = new Map<string, number>();
  for (const threat of threats) if (threat.primaryEvidence) counts.set(titleCase(threat.primaryEvidence.code), (counts.get(titleCase(threat.primaryEvidence.code)) ?? 0) + 1);
  return [...counts].map(([name, count]) => ({ name, count, averageRisk: null, highCriticalCount: null })).sort((a, b) => b.count - a.count);
}

function fallbackAttention(users: UserSummary[]): EmployeeAttention[] {
  return users.filter((user) => user.latestRiskScore !== null).sort((a, b) => (b.latestRiskScore ?? 0) - (a.latestRiskScore ?? 0)).slice(0, 6).map((user) => ({ employeeId: user.employeeId, employeeName: user.employeeName, department: user.department, maximumRisk: user.latestRiskScore ?? 0, averageRisk: user.latestRiskScore ?? 0, eventCount: user.activityCount, activeAlertCount: user.alertCount }));
}

function fallbackThreatTrend(threats: ThreatSummary[]): ThreatTrendPoint[] {
  const daily = new Map<string, ThreatTrendPoint>();
  for (const threat of threats) {
    const date = threat.occurredAt.slice(0, 10);
    const point = daily.get(date) ?? { date, medium: 0, high: 0, critical: 0 };
    if (threat.riskLevel === "Medium") point.medium += 1;
    if (threat.riskLevel === "High") point.high += 1;
    if (threat.riskLevel === "Critical") point.critical += 1;
    daily.set(date, point);
  }
  return [...daily.values()].sort((a, b) => a.date.localeCompare(b.date));
}

function MetricCard({ icon: Icon, label, value, description, tone = "blue" }: { icon: typeof Activity; label: string; value: string; description: string; tone?: "blue" | "orange" | "red" | "green" }) {
  const tones = { blue: "bg-[#eaf2ff] text-[#2563eb]", orange: "bg-[#fff3e9] text-[#ea6b22]", red: "bg-[#fff0f1] text-[#dc3545]", green: "bg-[#eaf8f1] text-[#1f9d68]" };
  return <article className="panel interactive-panel min-w-0 p-4"><div className="flex items-start justify-between gap-3"><div><p className="text-[11px] font-semibold text-[var(--text-secondary)]">{label}</p><p className="mt-2 text-[25px] font-bold tracking-[-0.035em] tabular">{value}</p></div><span className={`grid size-9 shrink-0 place-items-center rounded-xl ${tones[tone]}`}><Icon className="size-4" /></span></div><p className="mt-3 text-[9px] leading-4 text-[var(--text-muted)]">{description}</p></article>;
}

function CardHeader({ title, description, info }: { title: string; description: string; info?: string }) {
  return <div className="flex items-start justify-between gap-3"><div><h2 className="text-[14px] font-bold tracking-[-0.015em]">{title}</h2><p className="mt-1 text-[10px] leading-4 text-[var(--text-muted)]">{description}</p></div>{info && <span title={info} aria-label={info} className="grid size-7 shrink-0 place-items-center rounded-lg bg-[var(--surface-elevated)] text-[var(--text-muted)]"><Info className="size-3.5" /></span>}</div>;
}

export default async function OverviewPage() {
  const source = getSentinelDataSource();
  const [overview, threats, system, counts, users] = await Promise.all([source.getOverview(), source.listThreats(), source.getSystemStatus(), source.getCounts(), source.listUsers({ sort: "risk", direction: "desc", pageSize: 100 })]);
  const total = overview.totalEvents ?? counts.detections;
  const averageRisk = overview.averageRiskScore ?? overview.riskActivity.reduce((sum, point) => sum + point.averageRisk, 0) / Math.max(1, overview.riskActivity.length);
  const activeAlerts = overview.activeAlerts ?? Object.values(overview.activeThreats).reduce((sum, value) => sum + value, 0);
  const highRisk = overview.highRiskEvents ?? overview.riskDistribution.High + overview.riskDistribution.Critical;
  const critical = overview.criticalThreats ?? overview.riskDistribution.Critical;
  const security = posture(averageRisk);
  const trend: ThreatTrendPoint[] = overview.threatTrend ?? fallbackThreatTrend(threats);
  const threatTypes = overview.threatTypes ?? fallbackThreatTypes(threats);
  const contribution = overview.detectionContribution;
  const attention = overview.employeesRequiringAttention ?? fallbackAttention(users.items);
  const recent = [...threats].sort((a, b) => b.occurredAt.localeCompare(a.occurredAt)).slice(0, 6);
  const criticalAlerts = threats.filter((threat) => threat.riskLevel === "Critical").slice(0, 5);

  return <div className="mx-auto max-w-[1560px] space-y-5">
    <section className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
      <div><p className="text-[10px] font-bold uppercase tracking-[0.14em] text-[var(--accent)]">SentinelAI Command Centre</p><h1 className="mt-2 text-[28px] font-bold tracking-[-0.035em]">Security Overview</h1><p className="mt-2 max-w-2xl text-[12px] text-[var(--text-secondary)]">Behavioural intelligence and threat activity across the monitored environment.</p></div>
      <div className="flex flex-wrap gap-2" aria-label="Live system status">
        <span className="inline-flex items-center gap-2 rounded-full border border-[#dce9e3] bg-white px-3 py-2 text-[10px] font-semibold"><Database className="size-3.5 text-[var(--low)]" />Database Connected</span>
        <span className="inline-flex items-center gap-2 rounded-full border border-[#dfe7f6] bg-white px-3 py-2 text-[10px] font-semibold"><BrainCircuit className="size-3.5 text-[var(--accent)]" />AI Model {system.model.status === "ready" ? "Ready" : titleCase(system.model.status)}</span>
        <span className="inline-flex items-center gap-2 rounded-full border border-[#dce9e3] bg-white px-3 py-2 text-[10px] font-semibold"><ShieldCheck className="size-3.5 text-[var(--low)]" />System Healthy</span>
      </div>
    </section>

    <section aria-label="Security key metrics" className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
      <MetricCard icon={Activity} label="Total Events" value={total.toLocaleString()} description="Events analysed by SentinelAI" />
      <MetricCard icon={CircleAlert} label="Active Alerts" value={activeAlerts.toLocaleString()} description="Require investigation" tone="orange" />
      <MetricCard icon={TrendingUp} label="High-Risk Events" value={highRisk.toLocaleString()} description="High and Critical anomalies" tone="orange" />
      <MetricCard icon={Siren} label="Critical Threats" value={critical.toLocaleString()} description="Immediate attention required" tone="red" />
      <MetricCard icon={Sparkles} label="Average Risk Score" value={averageRisk.toFixed(1)} description="Across analysed activity" tone="green" />
    </section>

    <section className="grid gap-4 xl:grid-cols-[minmax(0,1.7fr)_minmax(280px,.75fr)]">
      <article className="panel p-5"><CardHeader title="Threat Activity Trend" description="Detected Medium, High and Critical activity across the available period" /><div className="mt-3"><ThreatTrendChart points={trend} /></div></article>
      <article className="panel flex min-h-[360px] flex-col p-5"><CardHeader title="Overall Security Posture" description="Derived from the average persisted risk score" info="The posture uses the mean final risk score across all persisted detections. It is not a probability of attack." /><div className="flex flex-1 flex-col items-center justify-center py-5"><div className="relative grid size-44 place-items-center rounded-full" style={{ background: `conic-gradient(${security.color} ${Math.max(2, averageRisk) * 3.6}deg, #edf1f6 0)` }}><div className="grid size-[132px] place-items-center rounded-full bg-white text-center shadow-inner"><div><div className="text-[34px] font-bold tracking-[-0.05em] tabular">{averageRisk.toFixed(1)}</div><div className="text-[9px] font-semibold uppercase tracking-[.12em] text-[var(--text-muted)]">out of 100</div></div></div></div><div className="mt-4 rounded-full px-3 py-1.5 text-[11px] font-bold" style={{ color: security.color, background: `color-mix(in srgb, ${security.color}, white 90%)` }}>{security.label}</div><p className="mt-3 max-w-[260px] text-center text-[10px] leading-4 text-[var(--text-secondary)]">{security.message}</p></div></article>
    </section>

    <section className="grid gap-4 xl:grid-cols-[minmax(300px,.8fr)_minmax(0,1.5fr)]">
      <article className="panel p-5"><CardHeader title="Risk Distribution" description="Select a risk level to inspect matching activity" /><RiskDistributionChart distribution={overview.riskDistribution} /></article>
      <article className="panel p-5"><CardHeader title="Threats by Detection Type" description="Most frequently triggered explainable security rules" /><ThreatTypesChart items={threatTypes} /></article>
    </section>

    <section className="grid gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(320px,.8fr)]">
      <article className="panel p-5"><CardHeader title="Average Risk Score Over Time" description="Daily mean final risk across the most recent 30 days" /><AverageRiskChart points={overview.riskActivity} /></article>
      <article className="panel p-5"><CardHeader title="Detection Intelligence" description="How SentinelAI contributes to aggregate risk" info="SentinelAI combines explainable security rules, machine-learning anomaly detection and contextual severity." />{contribution ? <DetectionContributionChart contribution={contribution} /> : <div className="grid h-[215px] place-items-center text-center"><p className="max-w-[250px] text-[10px] text-[var(--text-muted)]">Contribution aggregates are available when connected to the live API.</p></div>}<p className="mt-1 rounded-lg bg-[var(--surface-elevated)] px-3 py-2 text-[9px] leading-4 text-[var(--text-muted)]">Isolation Forest measures deviation from learned normal behaviour. Quantum detection is not active.</p></article>
    </section>

    <section className="grid gap-4 xl:grid-cols-2">
      <article className="panel p-5"><CardHeader title="Employees Requiring Attention" description="Ranked by current risk and active alert volume" /><div className="mt-4 space-y-2.5">{attention.map((employee, index) => <Link key={employee.employeeId} href={`/users/${employee.employeeId}`} className="group flex items-center gap-3 rounded-xl border border-border p-3 transition-all hover:border-[#cbd9f0] hover:bg-[#f8fbff]"><span className="grid size-8 shrink-0 place-items-center rounded-lg bg-[var(--surface-elevated)] text-[10px] font-bold text-[var(--text-muted)]">{String(index + 1).padStart(2, "0")}</span><span className="min-w-0 flex-1"><span className="block truncate text-[11px] font-bold">{employee.employeeName}</span><span className="mt-0.5 block truncate text-[9px] text-[var(--text-muted)]">{employee.department} · {employee.eventCount} events · {employee.activeAlertCount} active alerts</span></span><span className="text-right"><span className="block text-[15px] font-bold tabular" style={{ color: employee.maximumRisk >= 70 ? "var(--critical)" : employee.maximumRisk >= 50 ? "var(--high)" : "var(--medium)" }}>{employee.maximumRisk.toFixed(1)}</span><span className="text-[8px] uppercase tracking-wider text-[var(--text-muted)]">peak risk</span></span><ArrowRight className="size-3.5 text-[var(--text-muted)] transition-transform group-hover:translate-x-0.5 group-hover:text-[var(--accent)]" /></Link>)}</div></article>
      <article className="panel p-5"><CardHeader title="Risk by Department" description="Average persisted risk; select a department to drill down" />{overview.departmentRisk?.length ? <DepartmentRiskChart items={overview.departmentRisk} /> : <div className="grid h-[270px] place-items-center text-center"><div><UsersRound className="mx-auto size-6 text-[var(--text-muted)]" /><p className="mt-3 text-[11px] font-semibold">Department aggregation unavailable</p><p className="mt-1 text-[9px] text-[var(--text-muted)]">Connect to the live API to view persisted department risk.</p></div></div>}</article>
    </section>

    <section className="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(320px,.85fr)]">
      <article className="panel p-5"><div className="flex items-start justify-between gap-4"><CardHeader title="Recent Critical Alerts" description="Immediate investigations with the highest persisted severity" /><Link href="/threats?risk=Critical" className="shrink-0 text-[10px] font-bold text-[var(--accent)] hover:text-[var(--accent-strong)]">View All Alerts</Link></div><div className="mt-4 grid gap-3 sm:grid-cols-2">{criticalAlerts.map((alert) => <Link key={alert.alertId} href={`/threats?focus=${alert.alertId}#${alert.alertId}`} className="interactive-panel rounded-xl border border-border p-4"><div className="flex items-center justify-between gap-2"><span className="rounded-full bg-[#fff0f1] px-2 py-1 text-[8px] font-bold uppercase tracking-wider text-[var(--critical)]">{alert.riskLevel}</span><span className="text-[9px] text-[var(--text-muted)]">{new Date(alert.occurredAt).toLocaleDateString("en", { day: "2-digit", month: "short" })}</span></div><h3 className="mt-3 text-[11px] font-bold">{alert.title}</h3><p className="mt-1 text-[9px] text-[var(--text-secondary)]">{alert.employeeName} · {alert.department}</p><div className="mt-3 flex items-end justify-between"><span className="text-[9px] font-semibold text-[var(--accent)]">View Investigation</span><span className="text-[18px] font-bold text-[var(--critical)] tabular">{alert.riskScore.toFixed(0)}</span></div></Link>)}</div></article>
      <article className="panel p-5"><CardHeader title="Recent Security Activity" description="Latest important persisted detections" /><div className="relative mt-5 space-y-4 before:absolute before:bottom-2 before:left-[5px] before:top-2 before:w-px before:bg-border">{recent.map((alert) => <Link key={alert.alertId} href={`/threats?focus=${alert.alertId}#${alert.alertId}`} className="relative flex gap-4 pl-0"><span className="relative z-10 mt-1 size-[11px] shrink-0 rounded-full border-2 border-white" style={{ background: riskColor[alert.riskLevel], boxShadow: `0 0 0 1px ${riskColor[alert.riskLevel]}` }} /><span className="min-w-0 flex-1"><span className="block text-[10px] font-bold">{alert.title}</span><span className="mt-1 block text-[9px] text-[var(--text-muted)]">{alert.employeeName} · {new Date(alert.occurredAt).toLocaleString("en", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" })}</span><span className="mt-1 block text-[9px] font-semibold" style={{ color: riskColor[alert.riskLevel] }}>Risk {alert.riskScore.toFixed(0)} · {alert.riskLevel}</span></span></Link>)}</div></article>
    </section>
  </div>;
}
