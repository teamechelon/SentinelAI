"""Attack Lab API integration tests."""

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from sentinel_ai.api import create_app


def test_attack_lab_run_is_persisted_and_traceable(tmp_path) -> None:
    app = create_app(tmp_path / "attack-lab.db", bootstrap_demo_data=True)
    with TestClient(app) as client:
        employee_id = client.get("/api/users?page_size=1").json()["items"][0]["employeeId"]
        response = client.post("/api/attack-lab/runs", json={
            "employeeId": employee_id,
            "scenario": "privilege_abuse",
            "startTime": datetime(2025, 7, 1, 12, 0, tzinfo=timezone.utc).isoformat(),
            "intensity": "standard",
        })
        assert response.status_code == 201
        document = response.json()
        assert document["status"] == "complete"
        assert len(document["events"]) == 3
        assert document["findings"][0]["code"] == "PRIVILEGE_ABUSE"
        assert all(item["simulationId"] == document["simulationId"] for item in document["events"])

        fetched = client.get(f"/api/attack-lab/runs/{document['simulationId']}")
        assert fetched.status_code == 200
        assert fetched.json()["eventIds"] == document["eventIds"]


def test_attack_lab_validates_scenario_and_employee(tmp_path) -> None:
    app = create_app(tmp_path / "attack-lab-errors.db", bootstrap_demo_data=True)
    payload = {"employeeId": "MISSING", "scenario": "invented", "startTime": "2025-07-01T12:00:00Z"}
    with TestClient(app) as client:
        response = client.post("/api/attack-lab/runs", json=payload)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "unknown_scenario"

        payload["scenario"] = "credential_attack"
        response = client.post("/api/attack-lab/runs", json=payload)
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "employee_not_found"
