"""SQLite persistence and investigation workflow tests."""

from datetime import datetime, timezone

import pytest

from sentinel_ai.baselines import build_profile
from sentinel_ai.domain import Alert, DetectionResult, ModelScore
from sentinel_ai.features import build_feature_vector
from sentinel_ai.storage import SentinelDatabase
from sentinel_ai.detection import combine_risk


def make_database(tmp_path, employee, normal_event):
    database = SentinelDatabase(tmp_path / "sentinel-test.db")
    database.initialize()
    database.insert_employees([employee])
    database.insert_events([normal_event])
    profile = build_profile(employee, [normal_event])
    database.upsert_profiles([profile])
    vector = build_feature_vector(normal_event, profile)
    result = combine_risk(
        normal_event,
        vector,
        (),
        ModelScore("ready", 0.2, 40.0, 0.0, "test", "normal"),
    )
    database.insert_detection(result)
    return database, profile, result


def test_database_round_trip(tmp_path, employee, normal_event) -> None:
    database, profile, result = make_database(tmp_path, employee, normal_event)

    assert database.get_employee(employee.employee_id) == employee
    assert database.get_event(normal_event.event_id) == normal_event
    assert database.get_profile(employee.employee_id) == profile
    assert database.list_detection_rows()[0]["event_id"] == result.event_id


def test_duplicate_event_is_idempotent(tmp_path, employee, normal_event) -> None:
    database, _, _ = make_database(tmp_path, employee, normal_event)

    assert database.insert_events([normal_event]) == 0
    assert len(database.list_activity_events()) == 1


def test_alert_status_and_notes_workflow(tmp_path, employee, normal_event) -> None:
    database, _, result = make_database(tmp_path, employee, normal_event)
    alert = Alert(
        alert_id="ALT-TEST",
        detection_id=result.detection_id,
        event_id=normal_event.event_id,
        employee_id=employee.employee_id,
        created_at=datetime.now(timezone.utc),
        status="New",
        title="Test alert",
        risk_score=60.0,
        risk_level="High",
    )

    assert database.create_alert(alert) is True
    assert database.create_alert(alert) is False
    database.update_alert_status(alert.alert_id, "Investigating")
    note_id = database.add_investigation_note(alert.alert_id, "Confirmed with the employee.")

    assert note_id > 0
    assert database.list_alert_rows()[0]["status"] == "Investigating"
    assert database.list_investigation_notes(alert.alert_id)[0]["note"] == "Confirmed with the employee."


def test_invalid_alert_mutations_are_rejected(tmp_path, employee, normal_event) -> None:
    database, _, _ = make_database(tmp_path, employee, normal_event)

    with pytest.raises(ValueError):
        database.update_alert_status("MISSING", "Closed")
    with pytest.raises(KeyError):
        database.update_alert_status("MISSING", "Resolved")
    with pytest.raises(ValueError):
        database.add_investigation_note("MISSING", "   ")


def test_previous_login_query_respects_time_boundary(tmp_path, employee, normal_event, event_factory) -> None:
    database, _, _ = make_database(tmp_path, employee, normal_event)
    later = event_factory(event_id="EVT-LATER", timestamp=normal_event.timestamp.replace(hour=12))
    database.insert_events([later])

    previous = database.previous_successful_login(employee.employee_id, later.timestamp)

    assert previous is not None
    assert previous.event_id == normal_event.event_id


def test_clear_all_returns_database_to_empty_state(tmp_path, employee, normal_event) -> None:
    database, _, _ = make_database(tmp_path, employee, normal_event)

    database.clear_all()

    assert database.is_empty()
    assert database.list_activity_events() == []
