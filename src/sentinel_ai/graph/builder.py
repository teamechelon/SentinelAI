from sentinel_ai.graph.models import SecurityGraph, GraphNode, GraphEdge
from sentinel_ai.domain import Employee, ActivityEvent

def build_security_graph(employees: list[Employee], events: list[ActivityEvent], detection_rows: list[dict], simulation_runs: list[dict]) -> SecurityGraph:
    graph = SecurityGraph()
    
    # 1. Employees and 2. Departments
    for emp in employees:
        emp_node_id = f"employee:{emp.employee_id}"
        graph.add_node(GraphNode(emp_node_id, "employee", emp.employee_name, {"department": emp.department}))
        
        dept_node_id = f"department:{emp.department}"
        if dept_node_id not in graph.nodes:
            graph.add_node(GraphNode(dept_node_id, "department", emp.department, {}))
            
        # 3. BELONGS_TO edges
        graph.add_edge(GraphEdge(emp_node_id, dept_node_id, "BELONGS_TO", {}))
        
    # detection rows lookup for risk level
    event_risk = {row["event_id"]: row.get("risk_level", "Low") for row in detection_rows}
        
    # 4. Iterate events
    for event in events:
        emp_node_id = f"employee:{event.employee_id}"
        event_node_id = f"event:{event.event_id}"
        event_risk_lvl = event_risk.get(event.event_id, "Low")
        
        event_meta = {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "activity_type": event.activity_type,
            "scenario": event.scenario,
            "risk_level": event_risk_lvl
        }
        
        # Event node
        if event_node_id not in graph.nodes:
            graph.add_node(GraphNode(event_node_id, "event", event.event_id, event_meta))
        
        # Employee -> GENERATED -> Event
        graph.add_edge(GraphEdge(emp_node_id, event_node_id, "GENERATED", event_meta))
        
        # device nodes
        if event.device_id:
            dev_node_id = f"device:{event.device_id}"
            if dev_node_id not in graph.nodes:
                graph.add_node(GraphNode(dev_node_id, "device", event.device_id, {}))
            graph.add_edge(GraphEdge(event_node_id, dev_node_id, "USED_DEVICE", event_meta))
            graph.add_edge(GraphEdge(emp_node_id, dev_node_id, "USES_DEVICE", event_meta))
            
        # ip_address nodes
        if event.ip_address:
            ip_node_id = f"ip_address:{event.ip_address}"
            if ip_node_id not in graph.nodes:
                graph.add_node(GraphNode(ip_node_id, "ip_address", event.ip_address, {}))
            graph.add_edge(GraphEdge(event_node_id, ip_node_id, "CONNECTED_FROM", event_meta))
            graph.add_edge(GraphEdge(emp_node_id, ip_node_id, "CONNECTS_FROM", event_meta))
            
        # location nodes
        if event.city and event.country:
            loc_label = f"{event.city}, {event.country}"
            loc_node_id = f"location:{loc_label}"
            if loc_node_id not in graph.nodes:
                graph.add_node(GraphNode(loc_node_id, "location", loc_label, {"city": event.city, "country": event.country}))
            graph.add_edge(GraphEdge(event_node_id, loc_node_id, "OCCURRED_AT", event_meta))
            graph.add_edge(GraphEdge(emp_node_id, loc_node_id, "LOGS_IN_FROM", event_meta))
            
        # file nodes
        if event.file_name and event.file_sensitivity in ("Confidential", "Restricted"):
            file_node_id = f"file:{event.file_name}"
            if file_node_id not in graph.nodes:
                graph.add_node(GraphNode(file_node_id, "file", event.file_name, {"sensitivity": event.file_sensitivity}))
            graph.add_edge(GraphEdge(event_node_id, file_node_id, "ACCESSED_FILE", event_meta))
            graph.add_edge(GraphEdge(emp_node_id, file_node_id, "ACCESSES_FILE", event_meta))
            
    # 5. Attack run nodes
    for run in simulation_runs:
        sim_id = run["simulation_id"]
        run_node_id = f"attack_run:{sim_id}"
        graph.add_node(GraphNode(run_node_id, "attack_run", f"Simulation {sim_id}", {"scenario": run.get("scenario")}))
        
        emp_node_id = f"employee:{run['employee_id']}"
        graph.add_edge(GraphEdge(emp_node_id, run_node_id, "ASSOCIATED_WITH_ATTACK", {}))
        
        for eid in run.get("event_ids", []):
            event_node_id = f"event:{eid}"
            if event_node_id in graph.nodes:
                graph.add_edge(GraphEdge(event_node_id, run_node_id, "PART_OF_ATTACK_RUN", {"event_id": eid}))
            
            # Also keep infra edges for backward compatibility
            event = next((e for e in events if e.event_id == eid), None)
            if event:
                if event.device_id:
                    graph.add_edge(GraphEdge(f"device:{event.device_id}", run_node_id, "PART_OF_ATTACK_RUN", {"event_id": eid}))
                if event.ip_address:
                    graph.add_edge(GraphEdge(f"ip_address:{event.ip_address}", run_node_id, "PART_OF_ATTACK_RUN", {"event_id": eid}))
                
    return graph
