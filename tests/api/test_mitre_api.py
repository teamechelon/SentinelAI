"""Public MITRE ATT&CK and threat-story API contract tests."""

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from sentinel_ai.api import create_app


def test_catalog_is_local_versioned_and_camel_case(tmp_path) -> None:
    with TestClient(create_app(tmp_path / "mitre-catalog.db")) as client:
        response = client.get("/api/mitre/catalog")
        assert response.status_code == 200
        document = response.json()
        assert document["sourceVersion"] == "Enterprise ATT&CK v19.2"
        assert {item["techniqueId"] for item in document["techniques"]} == {"T1110", "T1078", "T1098", "T1005"}
        assert all(item["sourceUrl"].startswith("https://attack.mitre.org/techniques/") for item in document["techniques"])


def test_attack_run_report_contains_story_mappings_and_support(tmp_path) -> None:
    with TestClient(create_app(tmp_path / "mitre-run.db")) as client:
        employee_id = client.get("/api/users?page_size=1").json()["items"][0]["employeeId"]
        run = client.post("/api/attack-lab/runs", json={
            "employeeId": employee_id,
            "scenario": "account_compromise",
            "startTime": datetime(2025, 7, 1, 12, 0, tzinfo=timezone.utc).isoformat(),
            "intensity": "standard",
        }).json()
        response = client.get(f"/api/mitre/attack-runs/{run['simulationId']}")
        assert response.status_code == 200
        document = response.json()
        assert document["subjectType"] == "attack_run"
        assert {item["techniqueId"] for item in document["mappings"]} == {"T1110", "T1078", "T1005"}
        assert document["threatStory"]["mappedTechniqueIds"]
        assert document["sequenceEvidence"][0]["eventIds"]
        assert len(document["supportingEvents"]) == 3
        assert [item["timestamp"] for item in document["timeline"]] == sorted(item["timestamp"] for item in document["timeline"])

        event_id = run["eventIds"][0]
        event_response = client.get(f"/api/mitre/events/{event_id}")
        assert event_response.status_code == 200
        assert event_response.json()["subjectId"] == event_id

        alert = next(item for item in run["events"] if item["alertId"])
        alert_response = client.get(f"/api/mitre/alerts/{alert['alertId']}")
        assert alert_response.status_code == 200
        assert alert_response.json()["subjectType"] == "alert"


def test_mitre_not_found_errors_and_overview_contract(tmp_path) -> None:
    with TestClient(create_app(tmp_path / "mitre-errors.db")) as client:
        for path, code in (
            ("/api/mitre/events/MISSING", "event_not_found"),
            ("/api/mitre/attack-runs/MISSING", "simulation_not_found"),
            ("/api/mitre/alerts/MISSING", "alert_not_found"),
        ):
            response = client.get(path)
            assert response.status_code == 404
            assert response.json()["error"]["code"] == code
        overview = client.get("/api/mitre/overview")
        assert overview.status_code == 200
        assert overview.json()["affectsProductionRisk"] is False
