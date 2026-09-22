"""Export deterministic frontend demo data from the SentinelAI reference service."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict
from datetime import datetime
import json
import math
from pathlib import Path
from typing import Any

from sentinel_ai import config
from sentinel_ai.demo import SIMULATION_SCENARIOS
from sentinel_ai.services import SentinelService


FRONTEND_ROOT = Path(__file__).resolve().parents[1]
WORK_DATABASE = FRONTEND_ROOT / ".fixture-work" / "sentinel.db"
OUTPUT_PATH = FRONTEND_ROOT / "src" / "data" / "fixtures" / "sentinel-demo.v1.json"


def _iso_day(value: str) -> str:
    return datetime.fromisoformat(value).date().isoformat()


def _humanize(value: str) -> str:
    return value.replace("_", " ").strip().title()


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1))
    return round(ordered[index], 2)


def _evidence(rule: dict[str, Any]) -> dict[str, Any]:
    return {
        "code": rule["rule_name"],
        "reason": rule["reason"],
        "observed": rule["observed_value"],
        "expected": rule["expected_value"],
        "contribution": float(rule["contribution"]),
    }


def _employee(item: Any) -> dict[str, Any]:
    row = asdict(item)
    return {
        "employeeId": row["employee_id"],
        "employeeName": row["employee_name"],
        "department": row["department"],
        "homeCountry": row["home_country"],
        "homeCity": row["home_city"],
        "homeLatitude": row["home_latitude"],
        "homeLongitude": row["home_longitude"],
        "knownDevices": list(row["known_devices"]),
        "normalPrivilege": row["normal_privilege"],
    }


def _profile(item: Any) -> dict[str, Any]:
    row = asdict(item)
    return {
        "employeeId": row["employee_id"],
        "normalLoginStart": row["normal_login_start"],
        "normalLoginEnd": row["normal_login_end"],
        "usualCountries": list(row["usual_countries"]),
        "usualCities": list(row["usual_cities"]),
        "knownDevices": list(row["known_devices"]),
        "averageDownloadCount": row["average_download_count"],
        "averageDownloadSizeMb": row["average_download_size_mb"],
        "typicalFileSensitivity": list(row["typical_file_sensitivity"]),
        "normalPrivilege": row["normal_privilege"],
        "averageFailedLoginCount": row["average_failed_login_count"],
        "historyEventCount": row["history_event_count"],
        "confidence": row["confidence"],
    }


def _activity(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "eventId": row["event_id"],
        "employeeId": row["employee_id"],
        "employeeName": row["employee_name"],
        "department": row["department"],
        "occurredAt": row["timestamp"],
        "activityType": row["activity_type"],
        "scenario": row["scenario"],
        "loginSuccess": bool(row["login_success"]),
        "failedLoginCount": int(row["failed_login_count"]),
        "ipAddress": row["ip_address"],
        "country": row["country"],
        "city": row["city"],
        "latitude": row["latitude"],
        "longitude": row["longitude"],
        "deviceId": row["device_id"],
        "isKnownDevice": bool(row["is_known_device"]),
        "resourceName": row["file_name"] or None,
        "resourceSensitivity": row["file_sensitivity"],
        "downloadCount": int(row["download_count"]),
        "downloadSizeMb": float(row["download_size_mb"]),
        "previousPrivilege": row["previous_privilege"],
        "currentPrivilege": row["current_privilege"],
        "isSuspicious": bool(row["is_suspicious"]),
        "isApprovedTravel": bool(row["is_approved_travel"]),
        "riskScore": float(row["final_risk_score"]),
        "riskLevel": row["risk_level"],
        "alertId": row.get("alert_id"),
        "alertStatus": row.get("alert_status"),
    }


def _detection(row: dict[str, Any]) -> dict[str, Any]:
    rules = [_evidence(rule) for rule in row.get("triggered_rules", [])]
    return {
        "detectionId": row["detection_id"],
        "eventId": row["event_id"],
        "employeeId": row["employee_id"],
        "occurredAt": row["timestamp"],
        "riskScore": float(row["final_risk_score"]),
        "riskLevel": row["risk_level"],
        "channels": [
            {
                "key": "rule",
                "label": "Rule evidence",
                "value": float(row["rule_contribution"]),
                "availability": "available",
                "source": config.RULE_VERSION,
            },
            {
                "key": "classicalAnomaly",
                "label": "Classical anomaly",
                "value": float(row["ai_contribution"]),
                "availability": "available",
                "source": config.MODEL_VERSION,
            },
            {
                "key": "context",
                "label": "Context",
                "value": float(row["contextual_contribution"]),
                "availability": "available",
                "source": config.RULE_VERSION,
            },
            {
                "key": "assetSensitivity",
                "label": "Asset sensitivity",
                "value": None,
                "availability": "not_separately_scored",
                "source": "SENSITIVE_FILE_ACCESS evidence",
            },
            {
                "key": "quantumAnomaly",
                "label": "Quantum anomaly",
                "value": None,
                "availability": "not_implemented",
                "source": "none",
            },
        ],
        "anomalyPercentile": row["anomaly_percentile"],
        "modelStatus": row["model_status"],
        "evidence": rules,
        "explanation": row["explanation"],
        "recommendedResponse": row["recommended_response"],
        "featureValues": row.get("feature_values", {}),
    }


def _threat(row: dict[str, Any]) -> dict[str, Any]:
    rules = [_evidence(rule) for rule in row.get("triggered_rules", [])]
    return {
        "alertId": row["alert_id"],
        "eventId": row["event_id"],
        "employeeId": row["employee_id"],
        "employeeName": row["employee_name"],
        "department": row["department"],
        "title": row["title"],
        "activity": _humanize(row["activity_type"]),
        "story": _humanize(row["scenario"]),
        "riskScore": float(row["risk_score"]),
        "riskLevel": row["risk_level"],
        "primaryEvidence": rules[0] if rules else None,
        "evidenceCount": len(rules),
        "occurredAt": row["timestamp"],
        "createdAt": row["timestamp"],
        "status": row["status"],
    }


def main() -> None:
    WORK_DATABASE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    service = SentinelService(WORK_DATABASE)
    service.initialize(reseed=True)

    employees = service.employees()
    profiles = service.database.list_profiles()
    event_rows = service.event_rows()
    detection_rows = service.detection_rows()
    alert_rows = service.alert_rows()

    daily_risk: dict[str, list[float]] = defaultdict(list)
    daily_alerts: dict[str, int] = defaultdict(int)
    daily_anomaly: dict[str, list[float]] = defaultdict(list)
    for row in detection_rows:
        day = _iso_day(row["timestamp"])
        daily_risk[day].append(float(row["final_risk_score"]))
        if float(row["final_risk_score"]) >= config.ALERT_MINIMUM_SCORE:
            daily_alerts[day] += 1
        if row["anomaly_percentile"] is not None:
            daily_anomaly[day].append(float(row["anomaly_percentile"]))

    risk_activity = [
        {
            "date": day,
            "averageRisk": round(sum(values) / len(values), 2),
            "alertCount": daily_alerts[day],
        }
        for day, values in sorted(daily_risk.items())
    ]
    anomaly_activity = [
        {
            "date": day,
            "medianPercentile": _percentile(values, 0.5),
            "p95Percentile": _percentile(values, 0.95),
        }
        for day, values in sorted(daily_anomaly.items())
    ]

    risk_counts = {level: 0 for level in ("Low", "Medium", "High", "Critical")}
    for row in detection_rows:
        risk_counts[row["risk_level"]] += 1

    alert_counts = {level: 0 for level in ("Medium", "High", "Critical")}
    for row in alert_rows:
        if row["status"] not in {"Resolved", "False Positive"}:
            alert_counts[row["risk_level"]] += 1

    threats = sorted(
        (_threat(row) for row in alert_rows),
        key=lambda row: (row["riskScore"], row["occurredAt"], row["alertId"]),
        reverse=True,
    )

    normal_events_by_employee: dict[str, int] = defaultdict(int)
    for row in event_rows:
        if row["scenario"] == "normal" and not row["is_suspicious"]:
            normal_events_by_employee[row["employee_id"]] += 1
    training_rows = sum(count - max(1, int(count * 0.7)) for count in normal_events_by_employee.values())

    fixture = {
        "fixture": {
            "schemaVersion": "sentinel-demo.v1",
            "source": "sentinelai-python-reference",
            "classification": "development_demo_data",
            "randomSeed": config.RANDOM_SEED,
            "timestampPolicy": "volatile detection timestamps normalized to event time",
            "counts": {
                "employees": len(employees),
                "activityEvents": len(event_rows),
                "detections": len(detection_rows),
                "alerts": len(alert_rows),
            },
        },
        "system": {
            "mode": "LIVE",
            "model": {"status": service.model_status, "label": "Isolation Forest"},
            "database": {"status": "ready", "label": "SQLite"},
            "data": {"status": "development_demo_data", "label": "DEMO FIXTURE"},
            "operator": {"label": "LOCAL ANALYST", "session": "DEMO"},
        },
        "overview": {
            "activeThreats": alert_counts,
            "riskDistribution": risk_counts,
            "riskActivity": risk_activity,
            "anomalyActivity": anomaly_activity,
        },
        "employees": [_employee(item) for item in employees],
        "profiles": [_profile(profiles[key]) for key in sorted(profiles)],
        "activity": [_activity(row) for row in event_rows],
        "detections": [_detection(row) for row in detection_rows],
        "threats": threats,
        "simulations": [
            {"label": label, "scenario": scenario}
            for label, scenario in SIMULATION_SCENARIOS.items()
        ],
        "models": [
            {
                "name": "Isolation Forest",
                "status": service.model_status,
                "version": config.MODEL_VERSION,
                "featureSchemaVersion": config.FEATURE_SCHEMA_VERSION,
                "featureOrder": list(config.FEATURE_ORDER),
                "trainingRows": training_rows,
                "trainingScope": "Normal history only; final 30% per employee after baseline split",
                "anomalyDefinition": "Empirical nonconformity percentile against normal training history; not an attack probability.",
            },
            {
                "name": "Quantum Kernel",
                "status": "not_implemented",
                "version": None,
                "featureSchemaVersion": None,
                "featureOrder": [],
                "trainingRows": None,
                "trainingScope": None,
                "anomalyDefinition": None,
            },
        ],
    }

    OUTPUT_PATH.write_text(json.dumps(fixture, indent=2, sort_keys=True), encoding="utf-8")
    print(
        f"Exported {len(event_rows)} events, {len(detection_rows)} detections, "
        f"and {len(alert_rows)} alerts to {OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()
