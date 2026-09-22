"""Public API data-transfer objects."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


def _camel(value: str) -> str:
    parts = value.split("_")
    return parts[0] + "".join(part.capitalize() for part in parts[1:])


class ApiModel(BaseModel):
    model_config = ConfigDict(alias_generator=_camel, populate_by_name=True)


class PageMeta(ApiModel):
    page: int
    page_size: int
    total: int
    total_pages: int


class EvidenceSummaryDto(ApiModel):
    code: str
    contribution: float
    expected: str
    observed: str
    reason: str


class ThreatSummaryDto(ApiModel):
    activity: str
    alert_id: str
    created_at: datetime
    department: str
    employee_id: str
    employee_name: str
    event_id: str
    evidence_count: int
    occurred_at: datetime
    primary_evidence: EvidenceSummaryDto | None
    risk_level: str
    risk_score: float
    status: str
    story: str
    title: str


class SystemPartDto(ApiModel):
    label: str
    status: str


class OperatorDto(ApiModel):
    label: str
    session: str


class SystemCountsDto(ApiModel):
    employees: int
    activity_events: int
    detections: int
    alerts: int


class SystemStatusDto(ApiModel):
    mode: str
    data: SystemPartDto
    database: SystemPartDto
    model: SystemPartDto
    operator: OperatorDto
    counts: SystemCountsDto


class RiskPointDto(ApiModel):
    date: str
    alert_count: int
    average_risk: float


class AnomalyPointDto(ApiModel):
    date: str
    median_percentile: float
    p95_percentile: float


class ThreatTrendPointDto(ApiModel):
    date: str
    medium: int
    high: int
    critical: int


class NamedMetricDto(ApiModel):
    name: str
    count: int
    average_risk: float | None = None
    high_critical_count: int | None = None


class DetectionContributionDto(ApiModel):
    rule_based: float
    ai_anomaly: float
    contextual: float


class EmployeeAttentionDto(ApiModel):
    employee_id: str
    employee_name: str
    department: str
    maximum_risk: float
    average_risk: float
    event_count: int
    active_alert_count: int


class OverviewDto(ApiModel):
    active_threats: dict[str, int]
    risk_distribution: dict[str, int]
    risk_activity: list[RiskPointDto]
    anomaly_activity: list[AnomalyPointDto]
    total_events: int
    active_alerts: int
    high_risk_events: int
    critical_threats: int
    average_risk_score: float
    threat_trend: list[ThreatTrendPointDto]
    threat_types: list[NamedMetricDto]
    detection_contribution: DetectionContributionDto
    employees_requiring_attention: list[EmployeeAttentionDto]
    department_risk: list[NamedMetricDto]


class ActivityRecordDto(ApiModel):
    event_id: str
    occurred_at: datetime
    employee_id: str
    employee_name: str
    department: str
    activity_type: str
    scenario: str
    device_id: str
    is_known_device: bool
    ip_address: str
    city: str
    country: str
    resource_name: str | None
    resource_sensitivity: str
    previous_privilege: str
    current_privilege: str
    failed_login_count: int
    download_count: int
    download_size_mb: float
    risk_score: float | None
    risk_level: str | None
    anomaly_percentile: float | None
    is_anomalous: bool
    alert_id: str | None
    alert_status: str | None
    simulation_id: str | None = None


class ActivityPageDto(ApiModel):
    items: list[ActivityRecordDto]
    page: PageMeta


class ThreatPageDto(ApiModel):
    items: list[ThreatSummaryDto]
    page: PageMeta


class PeerGroupDto(ApiModel):
    department: str
    role: str


class UserSummaryDto(ApiModel):
    employee_id: str
    employee_name: str
    department: str
    role: str
    peer_group: PeerGroupDto
    profile_confidence: float
    history_event_count: int
    activity_count: int
    alert_count: int
    latest_risk_score: float | None
    latest_risk_level: str | None


class UserPageDto(ApiModel):
    items: list[UserSummaryDto]
    page: PageMeta


class PersonalBaselineDto(ApiModel):
    normal_login_start: float
    normal_login_end: float
    usual_countries: list[str]
    usual_cities: list[str]
    known_devices: list[str]
    average_download_count: float
    average_download_size_mb: float
    typical_file_sensitivity: list[str]
    normal_privilege: str
    average_failed_login_count: float
    history_event_count: int
    confidence: float


class PeerBaselineDto(ApiModel):
    peer_group: PeerGroupDto
    member_count: int
    contributing_member_count: int
    normal_login_start: float | None
    normal_login_end: float | None
    usual_countries: list[str]
    usual_cities: list[str]
    known_devices: list[str]
    average_download_count: float | None
    average_download_size_mb: float | None
    typical_file_sensitivity: list[str]
    normal_privilege: str
    average_failed_login_count: float | None
    history_event_count: int
    confidence: float
    status: str


class BehaviouralSignalDto(ApiModel):
    signal_name: str
    is_unusual: bool
    observed_value: str
    expected_value: str


class BehaviouralAssessmentDto(ApiModel):
    event_id: str
    employee_id: str
    peer_group: PeerGroupDto
    personal_deviation: float | None
    peer_deviation: float | None
    personal_confidence: float
    peer_confidence: float
    personal_status: str
    peer_status: str
    comparison_case: str
    personal_signals: list[BehaviouralSignalDto]
    peer_signals: list[BehaviouralSignalDto]


class DetectionHistoryDto(ApiModel):
    detection_id: str
    event_id: str
    occurred_at: datetime
    risk_score: float
    risk_level: str
    anomaly_percentile: float | None
    model_status: str


class UserDetailDto(ApiModel):
    employee_id: str
    employee_name: str
    department: str
    role: str
    home_city: str
    home_country: str
    peer_group: PeerGroupDto
    personal_baseline: PersonalBaselineDto
    peer_baseline: PeerBaselineDto
    current_assessment: BehaviouralAssessmentDto | None
    risk_history: list[DetectionHistoryDto]
    activity_history: list[ActivityRecordDto]
    related_alerts: list[ThreatSummaryDto]


class ModelMetadataDto(ApiModel):
    name: str
    implementation: str
    version: str
    status: str
    feature_schema_version: str
    feature_order: list[str]
    training_rows: int
    training_scope: str
    estimator_configuration: dict[str, Any]
    anomaly_definition: str


class ApiErrorDetail(ApiModel):
    code: str
    message: str


class ApiError(ApiModel):
    error: ApiErrorDetail


class AttackLabRunRequest(ApiModel):
    employee_id: str
    scenario: str
    start_time: datetime
    intensity: str = Field(default="standard", pattern="^(standard|elevated)$")


class AttackLabScenarioDto(ApiModel):
    scenario: str
    label: str
    event_count: int
    description: str


class SequenceFindingDto(ApiModel):
    code: str
    title: str
    severity: str
    status: str
    event_ids: list[str]
    window_minutes: int
    evidence: list[str]


class AttackLabRunDto(ApiModel):
    simulation_id: str
    employee_id: str
    scenario: str
    start_time: datetime
    intensity: str
    status: str
    created_at: datetime
    event_ids: list[str]
    findings: list[SequenceFindingDto]
    events: list[ActivityRecordDto]

class GraphNodeDto(ApiModel):
    node_id: str
    node_type: str
    label: str
    metadata: dict[str, Any] = Field(default_factory=dict)

class GraphEdgeDto(ApiModel):
    source_id: str
    target_id: str
    edge_type: str
    metadata: dict[str, Any] = Field(default_factory=dict)

class GraphFindingDto(ApiModel):
    finding_type: str
    severity: str
    entities: list[str]
    supporting_events: list[str]
    supporting_attack_runs: list[str]
    observed_relationship: str
    explanation: str

class GraphOverviewDto(ApiModel):
    node_count: int
    edge_count: int
    entity_counts: dict[str, int]
    finding_count: int
    high_severity_finding_count: int
    nodes: list[GraphNodeDto]
    edges: list[GraphEdgeDto]
    findings: list[GraphFindingDto]

class GraphEntityDetailDto(ApiModel):
    entity: GraphNodeDto
    connected_entities: list[GraphNodeDto]
    edges: list[GraphEdgeDto]
    findings: list[GraphFindingDto]
    event_ids: list[str]

class GraphEventContextDto(ApiModel):
    event_id: str
    entities: list[GraphNodeDto]
    findings: list[GraphFindingDto]

class GraphAttackRunContextDto(ApiModel):
    simulation_id: str
    employees: list[GraphNodeDto]
    devices: list[GraphNodeDto]
    ip_addresses: list[GraphNodeDto]
    locations: list[GraphNodeDto]
    files: list[GraphNodeDto]
    findings: list[GraphFindingDto]
    event_ids: list[str]

class GraphFindingsPageDto(ApiModel):
    items: list[GraphFindingDto]
    page: PageMeta

class GraphDataDto(ApiModel):
    nodes: list[GraphNodeDto]
    edges: list[GraphEdgeDto]
    findings: list[GraphFindingDto]
