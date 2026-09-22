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
}
