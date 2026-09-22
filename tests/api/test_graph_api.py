import pytest
from fastapi.testclient import TestClient
from sentinel_ai.api.app import create_app
from sentinel_ai.services import SentinelService

@pytest.fixture(scope="module")
def client(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("data") / "test_api.db"
    service = SentinelService(db_path)
    service.initialize(reseed=True)
    app = create_app(db_path)
    # inject the seeded service so the routes can use it
    app.state.service = service
    with TestClient(app) as test_client:
        yield test_client

def test_graph_overview_returns_counts(client):
    response = client.get("/api/graph/overview")
    assert response.status_code == 200
    data = response.json()
    assert "nodeCount" in data
    assert "edgeCount" in data

def test_graph_overview_is_summary_only(client):
    response = client.get("/api/graph/overview")
    data = response.json()
    assert data["nodeCount"] > 0
    assert data["edgeCount"] > 0
    assert "entityCounts" in data
    assert "event" in data["entityCounts"]
    assert "employee" in data["entityCounts"]
    assert "nodes" not in data
    assert "edges" not in data
    assert "findings" not in data


def test_graph_entity_detail_for_employee(client):
    response = client.get("/api/graph/entities/employee/EMP-001")
    assert response.status_code == 200
    data = response.json()
    assert "connectedEntities" in data

def test_graph_entity_unknown_returns_404(client):
    response = client.get("/api/graph/entities/employee/NONEXISTENT")
    assert response.status_code == 404

def test_graph_event_context(client):
    events_response = client.get("/api/activity")
    events = events_response.json()["items"]
    event_id = events[0]["eventId"]
    response = client.get(f"/api/graph/events/{event_id}")
    assert response.status_code == 200
    data = response.json()
    assert "entities" in data

def test_graph_findings_are_camel_case(client):
    response = client.get("/api/graph/findings")
    assert response.status_code == 200
    data = response.json()
    if data["items"]:
        finding = data["items"][0]
        assert "findingType" in finding
        assert "supportingEvents" in finding

def test_graph_findings_filter_by_severity(client):
    response = client.get("/api/graph/findings?severity=high")
    assert response.status_code == 200
    data = response.json()
    for item in data["items"]:
        assert item["severity"] == "high"

def test_graph_data_endpoint(client):
    response = client.get("/api/graph/data?maxNodes=50")
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "edges" in data
    assert "findings" in data
    assert len(data["nodes"]) <= 50
    if data["nodes"]:
        node = data["nodes"][0]
        assert "nodeId" in node
        assert "nodeType" in node

