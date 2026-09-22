"""Mapping between internal records and stable public API DTOs."""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime
from typing import Any

from sentinel_ai import config
from sentinel_ai.api.schemas import (
    ActivityRecordDto,
    AnomalyPointDto,
    BehaviouralAssessmentDto,
    BehaviouralSignalDto,
    DetectionHistoryDto,
    EvidenceSummaryDto,
    OverviewDto,
    PeerBaselineDto,
    PeerGroupDto,
    PersonalBaselineDto,
    RiskPointDto,
    ThreatSummaryDto,
)
from sentinel_ai.domain import BehaviouralAssessment, BehaviourProfile, PeerBehaviourProfile


def humanize(value: str) -> str:
    return value.replace("_", " ").strip().title()


def evidence(rule: dict[str, Any]) -> EvidenceSummaryDto:
    return EvidenceSummaryDto(
        code=rule["rule_name"],
        reason=rule["reason"],
        observed=rule["observed_value"],
        expected=rule["expected_value"],
        contribution=float(rule["contribution"]),
    )


def threat(row: dict[str, Any]) -> ThreatSummaryDto:
    rules = [evidence(rule) for rule in row.get("triggered_rules", [])]
    timestamp = datetime.fromisoformat(str(row["timestamp"]))
    return ThreatSummaryDto(
        alert_id=str(row["alert_id"]),
        event_id=str(row["event_id"]),
        employee_id=str(row["employee_id"]),
        employee_name=str(row["employee_name"]),
        department=str(row["department"]),
        title=str(row["title"]),
        activity=humanize(str(row["activity_type"])),
        story=humanize(str(row["scenario"])),
        risk_score=float(row["risk_score"]),
        risk_level=str(row["risk_level"]),
        primary_evidence=rules[0] if rules else None,
        evidence_count=len(rules),
        occurred_at=timestamp,
        created_at=datetime.fromisoformat(str(row["created_at"])),
        status=str(row["status"]),
    )


def activity(row: dict[str, Any]) -> ActivityRecordDto:
    anomaly_percentile = row.get("anomaly_percentile")
    return ActivityRecordDto(
        event_id=str(row["event_id"]),
        occurred_at=datetime.fromisoformat(str(row["timestamp"])),
        employee_id=str(row["employee_id"]),
        employee_name=str(row["employee_name"]),
        department=str(row["department"]),
        activity_type=str(row["activity_type"]),
        scenario=str(row["scenario"]),
        device_id=str(row["device_id"]),
        is_known_device=bool(row["is_known_device"]),
        ip_address=str(row["ip_address"]),
        city=str(row["city"]),
        country=str(row["country"]),
        resource_name=str(row["file_name"]) or None,
        resource_sensitivity=str(row["file_sensitivity"]),
        previous_privilege=str(row["previous_privilege"]),
        current_privilege=str(row["current_privilege"]),
        failed_login_count=int(row["failed_login_count"]),
        download_count=int(row["download_count"]),
        download_size_mb=float(row["download_size_mb"]),
        risk_score=float(row["final_risk_score"]) if row.get("final_risk_score") is not None else None,
        risk_level=str(row["risk_level"]) if row.get("risk_level") is not None else None,
        anomaly_percentile=float(anomaly_percentile) if anomaly_percentile is not None else None,
        is_anomalous=anomaly_percentile is not None and float(anomaly_percentile) >= 95.0,
        alert_id=str(row["alert_id"]) if row.get("alert_id") else None,
        alert_status=str(row["alert_status"]) if row.get("alert_status") else None,
        simulation_id=str(row["simulation_id"]) if row.get("simulation_id") else None,
    )


def personal_baseline(profile: BehaviourProfile) -> PersonalBaselineDto:
    return PersonalBaselineDto(**asdict(profile))


def peer_group(department: str, role: str) -> PeerGroupDto:
    return PeerGroupDto(department=department, role=role)


def peer_baseline(profile: PeerBehaviourProfile) -> PeerBaselineDto:
    values = asdict(profile)
    values["peer_group"] = peer_group(profile.peer_group.department, profile.peer_group.role)
    return PeerBaselineDto(**values)


def behavioural_assessment(assessment: BehaviouralAssessment) -> BehaviouralAssessmentDto:
    return BehaviouralAssessmentDto(
        event_id=assessment.event_id,
        employee_id=assessment.employee_id,
        peer_group=peer_group(assessment.peer_group.department, assessment.peer_group.role),
        personal_deviation=assessment.personal_deviation,
        peer_deviation=assessment.peer_deviation,
        personal_confidence=assessment.personal_confidence,
        peer_confidence=assessment.peer_confidence,
        personal_status=assessment.personal_status,
        peer_status=assessment.peer_status,
        comparison_case=assessment.comparison_case,
        personal_signals=[BehaviouralSignalDto(**asdict(signal)) for signal in assessment.personal_signals],
        peer_signals=[BehaviouralSignalDto(**asdict(signal)) for signal in assessment.peer_signals],
    )


def detection_history(row: dict[str, Any]) -> DetectionHistoryDto:
    return DetectionHistoryDto(
        detection_id=str(row["detection_id"]),
        event_id=str(row["event_id"]),
        occurred_at=datetime.fromisoformat(str(row["timestamp"])),
        risk_score=float(row["final_risk_score"]),
        risk_level=str(row["risk_level"]),
        anomaly_percentile=float(row["anomaly_percentile"]) if row["anomaly_percentile"] is not None else None,
        model_status=str(row["model_status"]),
    )


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1))
    return round(ordered[index], 2)


def overview(detections: list[dict[str, Any]], alerts: list[dict[str, Any]]) -> OverviewDto:
    daily_risk: dict[str, list[float]] = defaultdict(list)
    daily_alerts: dict[str, int] = defaultdict(int)
    daily_anomaly: dict[str, list[float]] = defaultdict(list)
    risk_counts = {level: 0 for level in ("Low", "Medium", "High", "Critical")}
    for row in detections:
        day = datetime.fromisoformat(str(row["timestamp"])).date().isoformat()
        daily_risk[day].append(float(row["final_risk_score"]))
        risk_counts[str(row["risk_level"])] += 1
        if float(row["final_risk_score"]) >= config.ALERT_MINIMUM_SCORE:
            daily_alerts[day] += 1
        if row["anomaly_percentile"] is not None:
            daily_anomaly[day].append(float(row["anomaly_percentile"]))
    active = {level: 0 for level in ("Medium", "High", "Critical")}
    for row in alerts:
        if row["status"] not in {"Resolved", "False Positive"}:
            active[str(row["risk_level"])] += 1
    return OverviewDto(
        active_threats=active,
        risk_distribution=risk_counts,
        risk_activity=[
            RiskPointDto(date=day, average_risk=round(sum(values) / len(values), 2), alert_count=daily_alerts[day])
            for day, values in sorted(daily_risk.items())
        ],
        anomaly_activity=[
            AnomalyPointDto(date=day, median_percentile=_percentile(values, 0.5), p95_percentile=_percentile(values, 0.95))
            for day, values in sorted(daily_anomaly.items())
        ],
    )
