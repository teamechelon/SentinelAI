"""FastAPI read-path contracts for system, activity, users, threats, and models."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinel_ai.api import create_app


@pytest.fixture(scope="module")
def client(tmp_path_factory) -> TestClient:
    database_path = tmp_path_factory.mktemp("api-read") / "sentinel.db"
    with TestClient(create_app(database_path, bootstrap_demo_data=True)) as test_client:
        yield test_client


def test_system_status_exposes_real_counts(client: TestClient) -> None:
    response = client.get("/api/system/status")

    assert response.status_code == 200
    body = response.json()
    assert body["model"]["status"] == "ready"
    assert body["counts"] == {"employees": 30, "activityEvents": 1356, "detections": 1356, "alerts": 195}


def test_overview_exposes_persisted_visual_aggregates(client: TestClient) -> None:
    response = client.get("/api/overview")

    assert response.status_code == 200
    body = response.json()
    assert body["totalEvents"] == 1356
    assert body["averageRiskScore"] > 0
    assert sum(body["riskDistribution"].values()) == body["totalEvents"]
    assert body["threatTrend"]
    assert body["threatTypes"][0]["count"] > 0
    assert round(sum(body["detectionContribution"].values()), 0) == 100
    assert len(body["employeesRequiringAttention"]) == 6
    assert body["departmentRisk"]


def test_activity_is_paginated_sorted_and_filterable(client: TestClient) -> None:
    response = client.get(
        "/api/activity",
        params={"activity_type": "download", "department": "Engineering", "sort": "risk_score", "direction": "desc", "page_size": 5},
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body["items"]) == 5
    assert body["page"]["total"] > 5
    assert all(item["activityType"] == "download" and item["department"] == "Engineering" for item in body["items"])
    scores = [item["riskScore"] for item in body["items"]]
    assert scores == sorted(scores, reverse=True)


def test_activity_anomalous_filter_uses_persisted_model_percentile(client: TestClient) -> None:
    response = client.get("/api/activity", params={"anomalous_only": True, "page_size": 100})

    assert response.status_code == 200
    items = response.json()["items"]
    assert items
    assert all(item["isAnomalous"] and item["anomalyPercentile"] >= 95 for item in items)


def test_user_detail_exposes_personal_peer_and_actual_histories(client: TestClient) -> None:
    listing = client.get("/api/users", params={"department": "Engineering"})
    employee_id = listing.json()["items"][0]["employeeId"]
    response = client.get(f"/api/users/{employee_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["peerGroup"]["department"] == "Engineering"
    assert body["personalBaseline"]["historyEventCount"] > 0
    assert body["peerBaseline"]["memberCount"] >= 1
    assert body["currentAssessment"]["personalDeviation"] is not None
    assert body["riskHistory"]
    assert body["activityHistory"]
    assert all(item["employeeId"] == employee_id for item in body["activityHistory"])


def test_unknown_user_returns_structured_error(client: TestClient) -> None:
    response = client.get("/api/users/EMP-MISSING")

    assert response.status_code == 404
    assert response.json() == {"error": {"code": "employee_not_found", "message": "Unknown employee: EMP-MISSING"}}


def test_threats_and_model_metadata_are_backend_facts(client: TestClient) -> None:
    threats = client.get("/api/threats", params={"risk": "Critical", "page_size": 10}).json()
    models = client.get("/api/models").json()

    assert threats["page"]["total"] == 24
    assert all(item["riskLevel"] == "Critical" for item in threats["items"])
    assert models[0]["name"] == "Isolation Forest"
    assert models[0]["trainingRows"] == 360
    assert len(models[0]["featureOrder"]) == 11
