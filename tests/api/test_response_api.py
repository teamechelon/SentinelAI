"""Response API contracts and safe repeated requests."""

from dataclasses import replace

from fastapi.testclient import TestClient

from sentinel_ai.api import create_app
from tests.integration.test_response_containment import _result


def test_response_status_history_and_manual_endpoints(tmp_path, employee, normal_event) -> None:
    app = create_app(tmp_path / "response-api.db")
    with TestClient(app) as client:
        service = app.state.service
        event = replace(normal_event, event_id="EVT-API-RESPONSE")
        service.database.insert_employees([employee])
        service.database.insert_events([event])
        service._persist_result(event, _result(event, 80))
        employee_id = employee.employee_id
        alert_id = "ALT-EVT-API-RESPONSE"
        payload = {"alertId": alert_id, "reason": "Incident investigation", "actor": "Analyst"}

        initial = client.get(f"/api/response/users/{employee_id}")
        assert initial.status_code == 200
        assert initial.json()["containmentStatus"] == "NONE"
        assert initial.json()["simulated"] is True

        for endpoint, expected_account, expected_sessions in (
            ("block", "BLOCKED", "ACTIVE"),
            ("revoke-sessions", "BLOCKED", "REVOKED"),
            ("unblock", "ACTIVE", "REVOKED"),
            ("restore-sessions", "ACTIVE", "ACTIVE"),
            ("contain", "BLOCKED", "REVOKED"),
        ):
            response = client.post(f"/api/response/users/{employee_id}/{endpoint}", json=payload)
            assert response.status_code == 200
            assert response.json()["state"]["accountStatus"] == expected_account
            assert response.json()["state"]["sessionStatus"] == expected_sessions

        duplicate = client.post(f"/api/response/users/{employee_id}/contain", json=payload)
        assert duplicate.status_code == 200
        assert duplicate.json()["actionRecorded"] is False

        history = client.get(f"/api/response/users/{employee_id}/history")
        assert history.status_code == 200
        assert len(history.json()["items"]) == 5
        assert history.json()["items"][0]["alertId"] == alert_id
        assert history.json()["items"][0]["riskScoreAtAction"] == 80


def test_response_api_validates_employee_alert_and_reason(tmp_path, employee, normal_event) -> None:
    app = create_app(tmp_path / "response-errors.db")
    with TestClient(app) as client:
        assert client.get("/api/response/users/MISSING").status_code == 404
        response = client.post(
            f"/api/response/users/{employee.employee_id}/block",
            json={"reason": "", "actor": "Analyst"},
        )
        assert response.status_code in {404, 422}
