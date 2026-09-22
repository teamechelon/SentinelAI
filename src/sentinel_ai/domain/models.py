"""Typed domain records shared across SentinelAI modules."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Employee:
    employee_id: str
    employee_name: str
    department: str
    home_country: str
    home_city: str
    home_latitude: float
    home_longitude: float
    known_devices: tuple[str, ...]
    normal_privilege: str = "Employee"


@dataclass(frozen=True)
class ActivityEvent:
    event_id: str
    employee_id: str
    employee_name: str
    department: str
    timestamp: datetime
    activity_type: str
    login_success: bool
    failed_login_count: int
    ip_address: str
    country: str
    city: str
    latitude: float | None
    longitude: float | None
    device_id: str
    is_known_device: bool
    file_name: str
    file_sensitivity: str
    download_count: int
    download_size_mb: float
    previous_privilege: str
    current_privilege: str
    scenario: str = "normal"
    is_suspicious: bool = False
    is_approved_travel: bool = False

    def to_record(self) -> dict[str, Any]:
        record = asdict(self)
        record["timestamp"] = self.timestamp.isoformat()
        record["login_success"] = int(self.login_success)
        record["is_known_device"] = int(self.is_known_device)
        record["is_suspicious"] = int(self.is_suspicious)
        record["is_approved_travel"] = int(self.is_approved_travel)
        return record


@dataclass(frozen=True)
class BehaviourProfile:
    employee_id: str
    normal_login_start: float
    normal_login_end: float
    usual_countries: tuple[str, ...]
    usual_cities: tuple[str, ...]
    known_devices: tuple[str, ...]
    average_download_count: float
    average_download_size_mb: float
    typical_file_sensitivity: tuple[str, ...]
    normal_privilege: str
    average_failed_login_count: float
    history_event_count: int
    confidence: float


@dataclass(frozen=True)
class FeatureVector:
    login_hour_deviation: float
    outside_working_hours: float
    unknown_device: float
    location_anomaly: float
    failed_login_count: float
    download_count_deviation: float
    download_size_deviation: float
    sensitive_file: float
    privilege_escalation: float
    travel_speed_kmh: float
    impossible_travel: float

    def as_mapping(self) -> dict[str, float]:
        return {key: float(value) for key, value in asdict(self).items()}


@dataclass(frozen=True)
class ModelScore:
    status: str
    raw_score: float | None
    anomaly_percentile: float | None
    contribution: float
    model_version: str
    message: str


@dataclass(frozen=True)
class RuleHit:
    rule_name: str
    contribution: float
    reason: str
    observed_value: str
    expected_value: str


@dataclass(frozen=True)
class DetectionResult:
    detection_id: str
    event_id: str
    employee_id: str
    detected_at: datetime
    final_risk_score: float
    risk_level: str
    rule_contribution: float
    ai_contribution: float
    contextual_contribution: float
    triggered_rules: tuple[RuleHit, ...]
    explanation: str
    recommended_response: str
    model_status: str
    model_raw_score: float | None
    anomaly_percentile: float | None
    feature_values: dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True)
class Alert:
    alert_id: str
    detection_id: str
    event_id: str
    employee_id: str
    created_at: datetime
    status: str
    title: str
    risk_score: float
    risk_level: str

