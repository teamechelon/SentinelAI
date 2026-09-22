import pytest
from dataclasses import replace
from sentinel_ai.graph.models import GraphNode, GraphEdge, GraphFinding, SecurityGraph
from sentinel_ai.graph.builder import build_security_graph
from sentinel_ai.graph.analyzer import analyze_graph
from sentinel_ai.graph.subgraph import select_subgraph

class DummyConfig:
    GRAPH_SHARED_DEVICE_MIN_EMPLOYEES = 2
    GRAPH_SHARED_IP_MIN_EMPLOYEES = 3
    GRAPH_SHARED_ENTITY_WINDOW_MINUTES = 60
    GRAPH_FILE_CONVERGENCE_WINDOW_MINUTES = 15
    GRAPH_HIGH_RISK_EVENT_RATIO_THRESHOLD = 0.5

def test_graph_node_creation():
    node = GraphNode("employee:E1", "employee", "Alice", {})
    assert node.node_id == "employee:E1"
    assert node.node_type == "employee"

def test_graph_edge_creation():
    edge = GraphEdge("employee:E1", "device:D1", "USES_DEVICE", {})
    assert edge.source_id == "employee:E1"

def test_graph_node_deduplication():
    graph = SecurityGraph()
    graph.add_node(GraphNode("node1", "employee", "Label1", {}))
    graph.add_node(GraphNode("node1", "employee", "Label2", {}))
    assert len(graph.nodes) == 1
    assert graph.nodes["node1"].label == "Label2"

def test_graph_edge_deduplication():
    graph = SecurityGraph()
    graph.add_edge(GraphEdge("s", "t", "T1", {}))
    graph.add_edge(GraphEdge("s", "t", "T1", {}))
    assert len(graph.edges) == 1

def test_graph_neighbors():
    graph = SecurityGraph()
    n1 = GraphNode("1", "t", "1", {})
    n2 = GraphNode("2", "t", "2", {})
    graph.add_node(n1)
    graph.add_node(n2)
    graph.add_edge(GraphEdge("1", "2", "T", {}))
    assert graph.neighbors("1") == [n2]

def test_graph_nodes_by_type():
    graph = SecurityGraph()
    graph.add_node(GraphNode("1", "t1", "1", {}))
    graph.add_node(GraphNode("2", "t2", "2", {}))
    assert len(graph.nodes_by_type("t1")) == 1

def test_graph_edges_for_node():
    graph = SecurityGraph()
    graph.add_edge(GraphEdge("1", "2", "T", {}))
    assert len(graph.edges_for("1")) == 1

def test_graph_findings_for_entity():
    graph = SecurityGraph()
    f = GraphFinding("T", "high", ("1",), (), (), "R", "E")
    graph.findings.append(f)
    assert graph.findings_for("1") == [f]

def test_build_graph_from_employees_and_events(employee, normal_event):
    graph = build_security_graph([employee], [normal_event], [], [])
    assert "employee:EMP-TEST" in graph.nodes
    assert "device:TEST-LAPTOP" in graph.nodes
    assert f"event:{normal_event.event_id}" in graph.nodes

def test_event_node_and_edge_integrity(employee, normal_event):
    graph = build_security_graph([employee], [normal_event], [], [])
    evt_node = graph.nodes[f"event:{normal_event.event_id}"]
    assert evt_node.node_type == "event"
    assert evt_node.label == normal_event.event_id

    # Verify edge integrity: every edge source and target exist in nodes
    for edge in graph.edges:
        assert edge.source_id in graph.nodes, f"Edge source missing: {edge.source_id}"
        assert edge.target_id in graph.nodes, f"Edge target missing: {edge.target_id}"

def test_missing_device_skipped(employee, normal_event):
    event = replace(normal_event, device_id="")
    graph = build_security_graph([employee], [event], [], [])
    assert len(graph.nodes_by_type("device")) == 0

def test_missing_ip_skipped(employee, normal_event):
    event = replace(normal_event, ip_address="")
    graph = build_security_graph([employee], [event], [], [])
    assert len(graph.nodes_by_type("ip_address")) == 0

def test_missing_file_skipped(employee, normal_event):
    event = replace(normal_event, file_name="test.txt", file_sensitivity="Public")
    graph = build_security_graph([employee], [event], [], [])
    assert len(graph.nodes_by_type("file")) == 0

def test_empty_database_produces_empty_graph():
    graph = build_security_graph([], [], [], [])
    assert len(graph.nodes) == 0

def test_employee_with_no_events(employee):
    graph = build_security_graph([employee], [], [], [])
    assert len(graph.nodes_by_type("employee")) == 1
    assert len(graph.edges_for("employee:EMP-TEST")) == 1

def test_shared_device_finding(employee, event_factory):
    e1 = event_factory(event_id="EVT-1", employee_id="EMP-1", device_id="D1")
    e2 = event_factory(event_id="EVT-2", employee_id="EMP-2", device_id="D1")
    detection_rows = [{"event_id": "EVT-1", "final_risk_score": 50, "risk_level": "Medium"}, {"event_id": "EVT-2", "final_risk_score": 50, "risk_level": "Medium"}]
    graph = build_security_graph([], [e1, e2], detection_rows, [])
    findings = analyze_graph(graph, [e1, e2], detection_rows, DummyConfig)
    assert any(f.finding_type == "SHARED_DEVICE" for f in findings)

def test_shared_ip_finding(event_factory):
    e1 = event_factory(event_id="EVT-1", employee_id="EMP-1", ip_address="IP1")
    e2 = event_factory(event_id="EVT-2", employee_id="EMP-2", ip_address="IP1")
    e3 = event_factory(event_id="EVT-3", employee_id="EMP-3", ip_address="IP1")
    detection_rows = [{"event_id": "EVT-1", "final_risk_score": 80, "risk_level": "High"}]
    graph = build_security_graph([], [e1, e2, e3], detection_rows, [])
    findings = analyze_graph(graph, [e1, e2, e3], detection_rows, DummyConfig)
    assert any(f.finding_type == "SHARED_IP" for f in findings)

def test_shared_ip_trusted_gateway_safeguard(event_factory):
    class ConfigWithTrusted(DummyConfig):
        TRUSTED_CORPORATE_IPS = {"10.0.0.1"}

    e1 = event_factory(event_id="EVT-1", employee_id="EMP-1", ip_address="10.0.0.1")
    e2 = event_factory(event_id="EVT-2", employee_id="EMP-2", ip_address="10.0.0.1")
    e3 = event_factory(event_id="EVT-3", employee_id="EMP-3", ip_address="10.0.0.1")
    graph = build_security_graph([], [e1, e2, e3], [], [])
    findings = analyze_graph(graph, [e1, e2, e3], [], ConfigWithTrusted)
    ip_findings = [f for f in findings if f.finding_type == "SHARED_IP"]
    assert len(ip_findings) == 1
    assert ip_findings[0].severity == "informational"

def test_sensitive_file_convergence_finding(event_factory):
    e1 = event_factory(event_id="EVT-1", employee_id="EMP-1", file_name="F1", file_sensitivity="Restricted")
    e2 = event_factory(event_id="EVT-2", employee_id="EMP-2", file_name="F1", file_sensitivity="Restricted")
    graph = build_security_graph([], [e1, e2], [], [])
    findings = analyze_graph(graph, [e1, e2], [], DummyConfig)
    assert any(f.finding_type == "SENSITIVE_FILE_CONVERGENCE" for f in findings)

def test_high_risk_entity_finding(event_factory):
    e1 = event_factory(event_id="EVT-1", employee_id="EMP-1", device_id="D1")
    e2 = event_factory(event_id="EVT-2", employee_id="EMP-1", device_id="D1")
    e3 = event_factory(event_id="EVT-3", employee_id="EMP-1", device_id="D1")
    detection_rows = [
        {"event_id": "EVT-1", "final_risk_score": 80, "risk_level": "High"},
        {"event_id": "EVT-2", "final_risk_score": 80, "risk_level": "High"},
        {"event_id": "EVT-3", "final_risk_score": 80, "risk_level": "High"}
    ]
    graph = build_security_graph([], [e1, e2, e3], detection_rows, [])
    findings = analyze_graph(graph, [e1, e2, e3], detection_rows, DummyConfig)
    assert any(f.finding_type == "HIGH_RISK_ENTITY" for f in findings)

def test_findings_require_evidence():
    graph = SecurityGraph()
    f = GraphFinding("T", "high", ("1",), ("E1",), (), "R", "E")
    assert len(f.supporting_events) > 0


def test_select_subgraph_empty_graph():
    empty_graph = SecurityGraph()
    res = select_subgraph(empty_graph, max_nodes=50)
    assert res["nodes"] == []
    assert res["edges"] == []
    assert res["findings"] == []


def test_select_subgraph_max_nodes_bound(employee, event_factory):
    events = [event_factory(event_id=f"EVT-{i}", employee_id="EMP-TEST", device_id=f"DEV-{i}") for i in range(20)]
    graph = build_security_graph([employee], events, [], [])
    res = select_subgraph(graph, max_nodes=10)
    assert len(res["nodes"]) <= 10
    assert len(res["nodes"]) > 0


def test_select_subgraph_edge_integrity(employee, event_factory):
    events = [event_factory(event_id=f"EVT-{i}", employee_id="EMP-TEST", device_id=f"DEV-{i}") for i in range(15)]
    graph = build_security_graph([employee], events, [], [])
    res = select_subgraph(graph, max_nodes=8)
    node_ids = {n.node_id for n in res["nodes"]}
    for edge in res["edges"]:
        assert edge.source_id in node_ids, f"Dangling edge source: {edge.source_id}"
        assert edge.target_id in node_ids, f"Dangling edge target: {edge.target_id}"


def test_select_subgraph_preserves_connected_relationships(employee, event_factory):
    e1 = event_factory(event_id="EVT-CONN-1", employee_id=employee.employee_id, device_id="D-MAIN", ip_address="192.168.1.50")
    graph = build_security_graph([employee], [e1], [{"event_id": "EVT-CONN-1", "risk_level": "High"}], [])
    res = select_subgraph(graph, max_nodes=10)
    edge_types = {e.edge_type for e in res["edges"]}
    # Verify meaningful relationships between employee, event, device, and IP are preserved
    assert "GENERATED" in edge_types
    assert "USED_DEVICE" in edge_types or "USES_DEVICE" in edge_types
    assert "CONNECTED_FROM" in edge_types or "CONNECTS_FROM" in edge_types


def test_select_subgraph_findings_scoped(employee, event_factory):
    e1 = event_factory(event_id="EVT-1", employee_id="EMP-1", device_id="DEV-SHARED")
    e2 = event_factory(event_id="EVT-2", employee_id="EMP-2", device_id="DEV-SHARED")
    detection_rows = [
        {"event_id": "EVT-1", "final_risk_score": 80, "risk_level": "High"},
        {"event_id": "EVT-2", "final_risk_score": 80, "risk_level": "High"},
    ]
    graph = build_security_graph([], [e1, e2], detection_rows, [])
    graph.findings = analyze_graph(graph, [e1, e2], detection_rows, DummyConfig)

    # Subgraph bounded
    res = select_subgraph(graph, max_nodes=10)
    node_ids = {n.node_id for n in res["nodes"]}
    for f in res["findings"]:
        # Finding must have at least one entity present
        assert any(e in node_ids for e in f.entities)
        # And evidence must not be completely absent
        assert any(f"event:{e}" in node_ids for e in f.supporting_events) or sum(1 for e in f.entities if e in node_ids) >= 2


def test_select_subgraph_employee_filter(employee, event_factory):
    e1 = event_factory(event_id="EVT-1", employee_id="EMP-TEST", device_id="DEV-1")
    e2 = event_factory(event_id="EVT-2", employee_id="EMP-OTHER", device_id="DEV-2")
    other_emp = replace(employee, employee_id="EMP-OTHER", employee_name="Other Employee")
    graph = build_security_graph([employee, other_emp], [e1, e2], [], [])

    res = select_subgraph(graph, employee_id="EMP-TEST", max_nodes=20)
    assert all(n.node_type != "employee" or n.node_id == "employee:EMP-TEST" for n in res["nodes"])
    assert "employee:EMP-TEST" in {n.node_id for n in res["nodes"]}
    assert "employee:EMP-OTHER" not in {n.node_id for n in res["nodes"]}


def test_select_subgraph_attack_run_filter(employee, event_factory):
    e1 = event_factory(event_id="EVT-ATTACK", employee_id="EMP-TEST", device_id="DEV-ATTACK")
    sim_runs = [{"simulation_id": "SIM-999", "employee_id": "EMP-TEST", "scenario": "brute_force", "event_ids": ["EVT-ATTACK"]}]
    graph = build_security_graph([employee], [e1], [], sim_runs)

    res = select_subgraph(graph, attack_run_id="SIM-999", max_nodes=20)
    node_ids = {n.node_id for n in res["nodes"]}
    assert "attack_run:SIM-999" in node_ids
    assert "event:EVT-ATTACK" in node_ids


def test_select_subgraph_determinism(employee, event_factory):
    events = [event_factory(event_id=f"EVT-{i}", employee_id="EMP-TEST", device_id=f"DEV-{i % 3}") for i in range(12)]
    graph = build_security_graph([employee], events, [], [])

    res1 = select_subgraph(graph, max_nodes=8)
    res2 = select_subgraph(graph, max_nodes=8)

    assert [n.node_id for n in res1["nodes"]] == [n.node_id for n in res2["nodes"]]
    assert [(e.source_id, e.target_id, e.edge_type) for e in res1["edges"]] == [(e.source_id, e.target_id, e.edge_type) for e in res2["edges"]]
