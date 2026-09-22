import "server-only";
import type { ActivityFilters, ActivityRecord, AttackLabRun, AttackLabScenario, CreateAttackLabRun, ModelEvaluationReport, ModelMetadata, OperationsOverview, PageResult, QuantumEvaluationReport, SystemCounts, SystemStatusSnapshot, ThreatFilters, ThreatSummary, UserDetail, UserFilters, UserSummary } from "@/domain/sentinel";
import type { SentinelDataSource } from "@/data/sentinel-data-source";

interface ApiErrorDocument { error?: { code?: string; message?: string } }

export class SentinelApiError extends Error {
  constructor(public readonly status: number, public readonly code: string, message: string) {
    super(message);
    this.name = "SentinelApiError";
  }
}

function queryString(values: Record<string, string | number | boolean | undefined>) {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== "" && value !== "All") query.set(key, String(value));
  }
  const encoded = query.toString();
  return encoded ? `?${encoded}` : "";
}

export class HttpDataSource implements SentinelDataSource {
  readonly mode = "http" as const;
  constructor(private readonly baseUrl: string) {}

  private async get<T>(path: string): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, { cache: "no-store", headers: { accept: "application/json" } });
    if (!response.ok) {
      const document = await response.json().catch(() => ({})) as ApiErrorDocument;
      throw new SentinelApiError(response.status, document.error?.code ?? "api_error", document.error?.message ?? `SentinelAI API returned ${response.status}.`);
    }
    return response.json() as Promise<T>;
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, { method: "POST", cache: "no-store", headers: { accept: "application/json", "content-type": "application/json" }, body: JSON.stringify(body) });
    if (!response.ok) {
      const document = await response.json().catch(() => ({})) as ApiErrorDocument;
      throw new SentinelApiError(response.status, document.error?.code ?? "api_error", document.error?.message ?? `SentinelAI API returned ${response.status}.`);
    }
    return response.json() as Promise<T>;
  }

  getSystemStatus() { return this.get<SystemStatusSnapshot>("/api/system/status"); }
  async getCounts(): Promise<SystemCounts> {
    const status = await this.getSystemStatus();
    if (!status.counts) throw new SentinelApiError(502, "missing_counts", "SentinelAI API status did not include dataset counts.");
    return status.counts;
  }
  getOverview() { return this.get<OperationsOverview>("/api/overview"); }
  async listThreats(filters: ThreatFilters = {}) {
    const result = await this.get<PageResult<ThreatSummary>>(`/api/threats${queryString({ q: filters.q, risk: filters.risk, status: filters.status, page_size: 250 })}`);
    return result.items;
  }
  listActivity(filters: ActivityFilters = {}) {
    return this.get<PageResult<ActivityRecord>>(`/api/activity${queryString({
      q: filters.q, start: filters.start, end: filters.end, employee_id: filters.employeeId,
      department: filters.department, activity_type: filters.activityType, scenario: filters.scenario,
      risk_level: filters.riskLevel, anomalous_only: filters.anomalousOnly || undefined,
      sort: filters.sort, direction: filters.direction, page: filters.page, page_size: filters.pageSize,
    })}`);
  }
  listUsers(filters: UserFilters = {}) {
    return this.get<PageResult<UserSummary>>(`/api/users${queryString({
      q: filters.q, department: filters.department, role: filters.role, sort: filters.sort,
      direction: filters.direction, page: filters.page, page_size: filters.pageSize,
    })}`);
  }
  async getUser(employeeId: string) {
    try {
      return await this.get<UserDetail>(`/api/users/${encodeURIComponent(employeeId)}`);
    } catch (error) {
      if (error instanceof SentinelApiError && error.status === 404) return null;
      throw error;
    }
  }
  listAttackLabScenarios() { return this.get<AttackLabScenario[]>("/api/attack-lab/scenarios"); }
  createAttackLabRun(input: CreateAttackLabRun) { return this.post<AttackLabRun>("/api/attack-lab/runs", input); }
  async getAttackLabRun(simulationId: string) {
    try {
      return await this.get<AttackLabRun>(`/api/attack-lab/runs/${encodeURIComponent(simulationId)}`);
    } catch (error) {
      if (error instanceof SentinelApiError && error.status === 404) return null;
      throw error;
    }
  }
  listModels() { return this.get<ModelMetadata[]>("/api/models"); }
  getModelEvaluation() { return this.get<ModelEvaluationReport>("/api/models/evaluation"); }
  getQuantumEvaluation() { return this.get<QuantumEvaluationReport>("/api/models/quantum"); }
}
