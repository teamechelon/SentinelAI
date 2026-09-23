import pytest
from fastapi.testclient import TestClient
from sentinel_ai.api.app import create_app
from sentinel_ai.services import SentinelService

@pytest.fixture(scope="module")
def client(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("data") / "test_api.db"
    service = SentinelService(db_path)
    service.initialize(reseed=True)
    app = create_app(db_path, bootstrap_demo_data=True)
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
    assert len(data["nodes"]) > 0
    # Bounded graph must retain meaningful edges, not be reduced to arbitrary disconnected nodes
    assert len(data["edges"]) > 0
    node_ids = {n["nodeId"] for n in data["nodes"]}
    # Edge integrity: every source and target exists in nodes
    for edge in data["edges"]:
        assert edge["sourceId"] in node_ids, f"Dangling edge source: {edge['sourceId']}"
        assert edge["targetId"] in node_ids, f"Dangling edge target: {edge['targetId']}"

    # Findings must be scoped to returned graph
    for finding in data["findings"]:
        assert any(e in node_ids for e in finding["entities"])


def test_graph_data_employee_filter_api(client):
    response = client.get("/api/graph/data?employeeId=EMP-001&maxNodes=30")
    assert response.status_code == 200
    data = response.json()
    assert len(data["nodes"]) <= 30
    assert len(data["nodes"]) > 0
    # Ensure no unrelated employees are mixed in
    for node in data["nodes"]:
        if node["nodeType"] == "employee":
            assert node["nodeId"] == "employee:EMP-001"


def test_graph_data_attack_run_filter_api(client):
    # Get a simulation ID if available
    overview = client.get("/api/graph/overview").json()
    attack_count = overview.get("entityCounts", {}).get("attack_run", 0)
    if attack_count > 0:
        # Fetch data with attackRunId
        full_data = client.get("/api/graph/data?maxNodes=100").json()
        attack_node = next((n for n in full_data["nodes"] if n["nodeType"] == "attack_run"), None)
        if attack_node:
            sim_id = attack_node["nodeId"].replace("attack_run:", "")
            res = client.get(f"/api/graph/data?attackRunId={sim_id}&maxNodes=20")
            assert res.status_code == 200
            run_data = res.json()
            assert any(n["nodeId"] == attack_node["nodeId"] for n in run_data["nodes"])
            run_node_ids = {n["nodeId"] for n in run_data["nodes"]}
            for edge in run_data["edges"]:
                assert edge["sourceId"] in run_node_ids
                assert edge["targetId"] in run_node_ids
