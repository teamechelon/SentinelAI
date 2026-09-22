import "server-only";
import fixture from "@/data/fixtures/sentinel-demo.v1.json";
import type { ActivityFilters, ActivityRecord, AlertStatus, RiskLevel, SentinelFixture, ThreatFilters, UserFilters, UserSummary } from "@/domain/sentinel";
import { SentinelApiError } from "@/data/http-data-source";
import type { SentinelDataSource } from "@/data/sentinel-data-source";

const riskLevels = new Set<RiskLevel>(["Low", "Medium", "High", "Critical"]);
const alertStatuses = new Set<AlertStatus>(["New", "Investigating", "Resolved", "False Positive"]);

function validateFixture(value: unknown): asserts value is SentinelFixture {
  if (!value || typeof value !== "object") throw new Error("Sentinel fixture is not an object.");
  const candidate = value as Partial<SentinelFixture>;
  if (candidate.fixture?.schemaVersion !== "sentinel-demo.v1") throw new Error("Unsupported Sentinel fixture schema.");
  if (!candidate.system || !candidate.overview || !Array.isArray(candidate.threats) || !Array.isArray(candidate.activity) || !Array.isArray(candidate.employees) || !Array.isArray(candidate.profiles)) throw new Error("Sentinel fixture is missing required sections.");
  if (candidate.threats.length !== candidate.fixture.counts.alerts) throw new Error("Sentinel fixture alert count does not match the threat collection.");
  for (const threat of candidate.threats) {
    if (!riskLevels.has(threat.riskLevel) || !alertStatuses.has(threat.status)) throw new Error(`Invalid enum value in ${threat.alertId}.`);
    if (!Number.isFinite(threat.riskScore) || threat.riskScore < 0 || threat.riskScore > 100) throw new Error(`Invalid persisted risk score in ${threat.alertId}.`);
    if (threat.primaryEvidence && !threat.primaryEvidence.code) throw new Error(`Invalid primary evidence in ${threat.alertId}.`);
  }
}

const fixtureDocument: unknown = fixture;
validateFixture(fixtureDocument);
const data = fixtureDocument;

export const fixtureDataSource: SentinelDataSource = {
  mode: "fixture",
  getSystemStatus: async () => data.system,
  getCounts: async () => data.fixture.counts,
  getOverview: async () => data.overview,
  listThreats: async (filters: ThreatFilters = {}) => {
    const query = filters.q?.trim().toLowerCase();
    return data.threats.filter((threat) => {
      const matchesQuery = !query || [threat.alertId, threat.employeeId, threat.employeeName, threat.department, threat.title, threat.story, threat.primaryEvidence?.code ?? "", threat.primaryEvidence?.reason ?? ""]
        .some((value) => value.toLowerCase().includes(query));
      const matchesRisk = !filters.risk || filters.risk === "All" || threat.riskLevel === filters.risk;
      const matchesStatus = !filters.status || filters.status === "All" || threat.status === filters.status;
      return matchesQuery && matchesRisk && matchesStatus;
    });
  },
  listActivity: async (filters: ActivityFilters = {}) => {
    const query = filters.q?.trim().toLowerCase();
    const items: ActivityRecord[] = data.activity.map((item) => ({
      ...item,
      anomalyPercentile: null,
      isAnomalous: false,
      simulationId: null,
    })).filter((item) => {
      const timestamp = new Date(item.occurredAt).getTime();
      const matchesQuery = !query || [item.eventId, item.employeeId, item.employeeName, item.department, item.activityType, item.scenario, item.deviceId, item.ipAddress, item.city, item.country, item.resourceName ?? ""]
        .some((value) => value.toLowerCase().includes(query));
      return matchesQuery
        && (!filters.start || timestamp >= new Date(filters.start).getTime())
        && (!filters.end || timestamp <= new Date(filters.end).getTime())
        && (!filters.employeeId || item.employeeId === filters.employeeId)
        && (!filters.department || item.department === filters.department)
        && (!filters.activityType || item.activityType === filters.activityType)
        && (!filters.scenario || item.scenario === filters.scenario)
        && (!filters.riskLevel || filters.riskLevel === "All" || item.riskLevel === filters.riskLevel)
        && !filters.anomalousOnly;
    });
    const direction = filters.direction === "asc" ? 1 : -1;
    const sort = filters.sort ?? "timestamp";
    items.sort((left, right) => {
      const values = sort === "risk_score"
        ? [(left.riskScore ?? -1), (right.riskScore ?? -1)]
        : sort === "employee"
          ? [left.employeeName, right.employeeName]
          : sort === "activity_type"
            ? [left.activityType, right.activityType]
            : [left.occurredAt, right.occurredAt];
      return (values[0] < values[1] ? -1 : values[0] > values[1] ? 1 : 0) * direction;
    });
    const page = filters.page ?? 1;
    const pageSize = filters.pageSize ?? 50;
    const total = items.length;
    return { items: items.slice((page - 1) * pageSize, page * pageSize), page: { page, pageSize, total, totalPages: Math.max(1, Math.ceil(total / pageSize)) } };
  },
  listUsers: async (filters: UserFilters = {}) => {
    const query = filters.q?.trim().toLowerCase();
    const alerts = new Map<string, number>();
    const activities = new Map<string, number>();
    const latest = new Map<string, { score: number | null; level: RiskLevel | null; occurredAt: string }>();
    for (const item of data.activity) {
      activities.set(item.employeeId, (activities.get(item.employeeId) ?? 0) + 1);
      if (item.alertId) alerts.set(item.employeeId, (alerts.get(item.employeeId) ?? 0) + 1);
      const current = latest.get(item.employeeId);
      if (!current || item.occurredAt > current.occurredAt) latest.set(item.employeeId, { score: item.riskScore, level: item.riskLevel, occurredAt: item.occurredAt });
    }
    const profiles = new Map(data.profiles.map((profile) => [profile.employeeId, profile]));
    const items: UserSummary[] = data.employees.map((employee) => {
      const profile = profiles.get(employee.employeeId);
      const risk = latest.get(employee.employeeId);
      return {
        employeeId: employee.employeeId,
        employeeName: employee.employeeName,
        department: employee.department,
        role: employee.normalPrivilege,
        peerGroup: { department: employee.department, role: employee.normalPrivilege },
        profileConfidence: profile?.confidence ?? 0,
        historyEventCount: profile?.historyEventCount ?? 0,
        activityCount: activities.get(employee.employeeId) ?? 0,
        alertCount: alerts.get(employee.employeeId) ?? 0,
        latestRiskScore: risk?.score ?? null,
        latestRiskLevel: risk?.level ?? null,
      };
    }).filter((item) => (!query || [item.employeeId, item.employeeName, item.department, item.role].some((value) => value.toLowerCase().includes(query)))
      && (!filters.department || item.department === filters.department)
      && (!filters.role || item.role === filters.role));
    const direction = filters.direction === "desc" ? -1 : 1;
    const sort = filters.sort ?? "name";
    items.sort((left, right) => {
      const values = sort === "risk" ? [left.latestRiskScore ?? -1, right.latestRiskScore ?? -1]
        : sort === "activity" ? [left.activityCount, right.activityCount]
          : sort === "department" ? [`${left.department}:${left.employeeName}`, `${right.department}:${right.employeeName}`]
            : [left.employeeName, right.employeeName];
      return (values[0] < values[1] ? -1 : values[0] > values[1] ? 1 : 0) * direction;
    });
    const page = filters.page ?? 1;
    const pageSize = filters.pageSize ?? 50;
    const total = items.length;
    return { items: items.slice((page - 1) * pageSize, page * pageSize), page: { page, pageSize, total, totalPages: Math.max(1, Math.ceil(total / pageSize)) } };
  },
  getUser: async (employeeId: string) => {
    const employee = data.employees.find((item) => item.employeeId === employeeId);
    const personalBaseline = data.profiles.find((item) => item.employeeId === employeeId);
    if (!employee || !personalBaseline) return null;
    const activityHistory = data.activity.filter((item) => item.employeeId === employeeId).slice(0, 50).map((item) => ({ ...item, anomalyPercentile: null, isAnomalous: false, simulationId: null }));
    return {
      employeeId,
      employeeName: employee.employeeName,
      department: employee.department,
      role: employee.normalPrivilege,
      homeCity: employee.homeCity,
      homeCountry: employee.homeCountry,
      peerGroup: { department: employee.department, role: employee.normalPrivilege },
      personalBaseline,
      peerBaseline: null,
      currentAssessment: null,
      riskHistory: [],
      activityHistory,
      relatedAlerts: data.threats.filter((item) => item.employeeId === employeeId).slice(0, 50),
    };
  },
  listAttackLabScenarios: async () => [
    { scenario: "account_compromise", label: "Account compromise", eventCount: 3, description: "Authentication anomaly, unknown-device login, then sensitive access." },
    { scenario: "credential_attack", label: "Credential attack", eventCount: 2, description: "Failed authentication burst followed by a successful login." },
    { scenario: "privilege_abuse", label: "Privilege abuse", eventCount: 3, description: "Successful login, privilege escalation, then sensitive access." },
    { scenario: "data_exfiltration", label: "Data exfiltration", eventCount: 2, description: "Sensitive access followed by a bulk or large download." },
  ],
  createAttackLabRun: async () => { throw new SentinelApiError(409, "live_api_required", "Attack Lab runs require SENTINEL_DATA_SOURCE=http."); },
  getAttackLabRun: async () => null,
  listModels: async () => data.models,
  getModelEvaluation: async () => null,
  getQuantumEvaluation: async () => ({ status: "unavailable", reason: "Evaluation execution requires SENTINEL_DATA_SOURCE=http.", affectsProductionRisk: false }),
};
