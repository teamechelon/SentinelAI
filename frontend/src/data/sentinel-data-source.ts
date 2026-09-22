import type {
  ActivityFilters,
  ActivityRecord,
  AttackLabRun,
  AttackLabScenario,
  CreateAttackLabRun,
  OperationsOverview,
  ModelEvaluationReport,
  ModelMetadata,
  QuantumEvaluationReport,
  PageResult,
  SystemCounts,
  SystemStatusSnapshot,
  ThreatFilters,
  ThreatSummary,
  UserDetail,
  UserFilters,
  UserSummary,
  GraphOverview,
  GraphEntityDetail,
  GraphEventContext,
  GraphAttackRunContext,
  GraphFinding,
  GraphData,
  GraphFilters,
} from "@/domain/sentinel";

export interface SentinelDataSource {
  readonly mode: "fixture" | "http";
  getSystemStatus(): Promise<SystemStatusSnapshot>;
  getCounts(): Promise<SystemCounts>;
  getOverview(): Promise<OperationsOverview>;
  listThreats(filters?: ThreatFilters): Promise<ThreatSummary[]>;
  listActivity(filters?: ActivityFilters): Promise<PageResult<ActivityRecord>>;
  listUsers(filters?: UserFilters): Promise<PageResult<UserSummary>>;
  getUser(employeeId: string): Promise<UserDetail | null>;
  listAttackLabScenarios(): Promise<AttackLabScenario[]>;
  createAttackLabRun(input: CreateAttackLabRun): Promise<AttackLabRun>;
  getAttackLabRun(simulationId: string): Promise<AttackLabRun | null>;
  listModels(): Promise<ModelMetadata[]>;
  getModelEvaluation(): Promise<ModelEvaluationReport | null>;
  getQuantumEvaluation(): Promise<QuantumEvaluationReport>;
  getGraphOverview(): Promise<GraphOverview>;
  getGraphData(filters?: GraphFilters): Promise<GraphData>;
  getGraphEntityDetail(entityType: string, entityId: string): Promise<GraphEntityDetail | null>;
  getGraphEventContext(eventId: string): Promise<GraphEventContext | null>;
  getGraphAttackRunContext(simulationId: string): Promise<GraphAttackRunContext | null>;
  getGraphFindings(filters?: { severity?: string; findingType?: string; entityType?: string; employeeId?: string }): Promise<PageResult<GraphFinding>>;
}
