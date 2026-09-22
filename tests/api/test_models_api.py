"""Model evaluation API contracts."""

from fastapi.testclient import TestClient

from sentinel_ai.api import create_app


def test_model_reports_are_exposed_without_risk_integration(tmp_path) -> None:
    with TestClient(create_app(tmp_path / "models.db")) as client:
        evaluation = client.get("/api/models/evaluation")
        quantum = client.get("/api/models/quantum")

    assert evaluation.status_code == 200
    assert evaluation.json()["dataset"]["futureDataUsed"] is False
    assert quantum.status_code == 200
    assert quantum.json()["status"] == "ready"
    assert quantum.json()["affectsProductionRisk"] is False
