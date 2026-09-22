"""End-to-end simulation tests against a real seeded SQLite database."""

from __future__ import annotations

import shutil
from datetime import datetime, timezone

import pytest

from sentinel_ai.services import SentinelService


@pytest.fixture(scope="module")
def seeded_database(tmp_path_factory) -> str:
    path = tmp_path_factory.mktemp("seeded") / "sentinel.db"
    service = SentinelService(path)
    service.initialize(reseed=True)
    assert service.model_status == "ready"
    return str(path)


@pytest.fixture
def service(seeded_database, tmp_path) -> SentinelService:
    isolated_path = tmp_path / "scenario.db"
    shutil.copy2(seeded_database, isolated_path)
    application = SentinelService(isolated_path)
    application.initialize()
    return application


def simulate(service: SentinelService, scenario: str):
    employee_id = service.employees()[0].employee_id
    timestamp = datetime(2025, 6, 15, 12, 0, tzinfo=timezone.utc)
    return service.simulate(scenario, employee_id, now=timestamp)


def rule_codes(result) -> set[str]:
    return {hit.rule_name for hit in result.triggered_rules}


def test_seeded_dataset_and_model_are_ready(service) -> None:
    assert len(service.employees()) == 30
    assert len(service.event_rows()) >= 1_300
    assert service.model_status == "ready"


def test_normal_login_remains_low_risk(service) -> None:
    result = simulate(service, "normal_login")

    assert result.risk_level == "Low"
    assert result.final_risk_score < 30
    assert rule_codes(result) == set()


def test_unknown_device_is_explained(service) -> None:
    result = simulate(service, "unknown_device_login")

    assert "UNKNOWN_DEVICE" in rule_codes(result)
    assert result.rule_contribution >= 12
    assert "known-device baseline" in result.explanation


def test_impossible_travel_is_detected(service) -> None:
    result = simulate(service, "impossible_travel")

    assert {"UNUSUAL_LOCATION", "IMPOSSIBLE_TRAVEL"}.issubset(rule_codes(result))
    assert result.final_risk_score >= 50
    assert result.risk_level in {"Medium", "High", "Critical"}


def test_bulk_download_is_detected(service) -> None:
    result = simulate(service, "bulk_download")

    assert {"BULK_DOWNLOAD", "LARGE_DOWNLOAD"}.issubset(rule_codes(result))
    assert result.final_risk_score >= 40


def test_privilege_escalation_is_detected(service) -> None:
    result = simulate(service, "privilege_escalation")

    assert "PRIVILEGE_ESCALATION" in rule_codes(result)
    assert result.final_risk_score >= 30


def test_brute_force_attempt_is_detected(service) -> None:
    result = simulate(service, "brute_force_attempt")

    assert {"REPEATED_FAILED_LOGINS", "UNKNOWN_DEVICE"}.issubset(rule_codes(result))
    assert result.contextual_contribution >= 10


def test_combined_compromise_is_critical_and_capped(service) -> None:
    result = simulate(service, "combined_account_compromise")

    assert result.risk_level == "Critical"
    assert result.final_risk_score == 100
    assert len(result.triggered_rules) >= 7
    assert result.rule_contribution + result.ai_contribution + result.contextual_contribution >= 100


def test_legitimate_travel_reduces_location_false_positive(service) -> None:
    result = simulate(service, "legitimate_travel")

    assert "UNUSUAL_LOCATION" not in rule_codes(result)
    assert "IMPOSSIBLE_TRAVEL" not in rule_codes(result)
    assert result.risk_level == "Low"


def test_simulation_is_persisted_with_full_explanation(service) -> None:
    result = simulate(service, "privilege_escalation")
    row = next(row for row in service.detection_rows() if row["event_id"] == result.event_id)

    assert row["final_risk_score"] == result.final_risk_score
    assert row["triggered_rules"][0]["observed_value"]
    assert row["triggered_rules"][0]["expected_value"]
    assert row["feature_values"]
    assert row["recommended_response"]


def test_alert_investigation_flow_end_to_end(service) -> None:
    result = simulate(service, "combined_account_compromise")
    alert = next(row for row in service.alert_rows() if row["event_id"] == result.event_id)

    service.update_alert_status(alert["alert_id"], "Investigating")
    service.add_investigation_note(alert["alert_id"], "Escalated during scenario test.")

    updated = service.database.get_alert_row(alert["alert_id"])
    notes = service.database.list_investigation_notes(alert["alert_id"])
    assert updated is not None and updated["status"] == "Investigating"
    assert notes[0]["note"] == "Escalated during scenario test."
