"""Persistent automatic and manual simulated-containment workflows."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

from sentinel_ai.domain import DetectionResult
from sentinel_ai.response.models import ResponseAction
from sentinel_ai.services import SentinelService


def _result(event, score: float) -> DetectionResult:
    return DetectionResult(
        detection_id=f"DET-{event.event_id}",
        event_id=event.event_id,
        employee_id=event.employee_id,
        detected_at=event.timestamp,
        final_risk_score=score,
        risk_level="Critical" if score >= 80 else "High",
        rule_contribution=score,
        ai_contribution=0,
        contextual_contribution=0,
        triggered_rules=(),
        explanation="Persisted test risk.",
        recommended_response="Investigate.",
        model_status="ready",
        model_raw_score=None,
        anomaly_percentile=None,
    )


def _service(tmp_path, employee, event, *, enabled=True) -> tuple[SentinelService, object]:
    service = SentinelService(tmp_path / "response.db", auto_containment_enabled=enabled)
    service.initialize()
    service.database.insert_employees([employee])
    persisted_event = replace(event, event_id="EVT-RESPONSE")
    service.database.insert_events([persisted_event])
    return service, persisted_event


def test_risk_100_auto_contains_and_is_idempotent(tmp_path, employee, normal_event) -> None:
    service, event = _service(tmp_path, employee, normal_event)

    service._persist_result(event, _result(event, 100))
    state = service.containment_state(employee.employee_id)
    history = service.response_history(employee.employee_id)

    assert state.account_status.value == "BLOCKED"
    assert state.session_status.value == "REVOKED"
    assert state.containment_status.value == "CONTAINED"
    assert state.containment_mode.value == "AUTO"
    assert state.source_alert_id == "ALT-EVT-RESPONSE"
    assert state.risk_score_at_action == 100
    assert len(history) == 2
    assert {item.action for item in history} == {ResponseAction.BLOCK_USER, ResponseAction.REVOKE_SESSIONS}
    assert all(item.actor == "SentinelAI Response Policy" for item in history)
    assert all(item.created_at.tzinfo is not None for item in history)

    service.response.evaluate_alert("ALT-EVT-RESPONSE")
    assert len(service.response_history(employee.employee_id)) == 2


def test_below_threshold_and_disabled_policy_do_not_contain(tmp_path, employee, normal_event) -> None:
    below, below_event = _service(tmp_path / "below", employee, normal_event)
    below._persist_result(below_event, _result(below_event, 99))
    assert below.containment_state(employee.employee_id).containment_status.value == "NONE"
    assert below.response_history(employee.employee_id) == []

    disabled, disabled_event = _service(tmp_path / "disabled", employee, normal_event, enabled=False)
    disabled._persist_result(disabled_event, _result(disabled_event, 100))
    assert disabled.containment_state(employee.employee_id).containment_status.value == "NONE"
    assert disabled.response_history(employee.employee_id) == []


def test_manual_actions_audit_and_persistence(tmp_path, employee, normal_event) -> None:
    service, event = _service(tmp_path, employee, normal_event, enabled=False)
    service._persist_result(event, _result(event, 80))
    alert_id = "ALT-EVT-RESPONSE"

    state, recorded = service.perform_response_action(
        employee.employee_id, ResponseAction.BLOCK_USER, "Confirmed account compromise", "Analyst", alert_id,
    )
    assert recorded is True
    assert state.account_status.value == "BLOCKED"
    assert state.session_status.value == "ACTIVE"
    assert state.containment_status.value == "PARTIAL"

    _, recorded = service.perform_response_action(
        employee.employee_id, ResponseAction.BLOCK_USER, "Duplicate request", "Analyst", alert_id,
    )
    assert recorded is False

    state, _ = service.perform_response_action(
        employee.employee_id, ResponseAction.REVOKE_SESSIONS, "Incident investigation", "Analyst", alert_id,
    )
    assert state.containment_status.value == "CONTAINED"
    state, _ = service.perform_response_action(
        employee.employee_id, ResponseAction.UNBLOCK_USER, "Account owner verified", "Analyst", alert_id,
    )
    assert state.account_status.value == "ACTIVE"
    assert state.session_status.value == "REVOKED"
    state, _ = service.perform_response_action(
        employee.employee_id, ResponseAction.RESTORE_SESSIONS, "Investigation completed", "Analyst", alert_id,
    )
    assert state.containment_status.value == "NONE"
    state, _ = service.perform_response_action(
        employee.employee_id, ResponseAction.BLOCK_AND_REVOKE, "New confirmed incident", "Lead Analyst", alert_id,
    )
    assert state.containment_status.value == "CONTAINED"

    history = service.response_history(employee.employee_id)
    assert len(history) == 5
    assert {item.action for item in history} == set(ResponseAction)
    assert all(item.alert_id == alert_id and item.risk_score_at_action == 80 for item in history)
    assert all(item.mode.value == "MANUAL" and item.result.value == "SUCCESS" for item in history)

    restarted = SentinelService(service.database.path, auto_containment_enabled=False)
    restarted.initialize()
    assert restarted.containment_state(employee.employee_id) == state
    assert restarted.response_history(employee.employee_id) == history


def test_startup_evaluation_converges_without_duplicate_history(tmp_path, employee, normal_event) -> None:
    original, event = _service(tmp_path, employee, normal_event, enabled=False)
    original._persist_result(event, _result(event, 100))
    assert original.response_history(employee.employee_id) == []

    upgraded = SentinelService(original.database.path, auto_containment_enabled=True)
    upgraded.initialize()
    assert upgraded.containment_state(employee.employee_id).containment_status.value == "CONTAINED"
    assert len(upgraded.response_history(employee.employee_id)) == 2

    restarted = SentinelService(original.database.path, auto_containment_enabled=True)
    restarted.initialize()
    assert len(restarted.response_history(employee.employee_id)) == 2
