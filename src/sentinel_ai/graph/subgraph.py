"""Subgraphs and bounded graph generation for SentinelAI security investigation."""

from collections import defaultdict
from sentinel_ai.graph.models import SecurityGraph, GraphNode, GraphEdge, GraphFinding

# Priority ordering for investigation context neighbors:
# Employee -> Event -> Device -> IP -> Location -> File -> Attack Run -> Department
TYPE_ORDER: dict[str, int] = {
    "employee": 1,
    "event": 2,
    "device": 3,
    "ip_address": 4,
    "location": 5,
    "file": 6,
    "attack_run": 7,
    "department": 8,
}


def select_subgraph(
    graph: SecurityGraph,
    max_nodes: int | None = None,
    node_type: str | None = None,
    severity: str | None = None,
    employee_id: str | None = None,
    attack_run_id: str | None = None,
) -> dict[str, list]:
    """Select a coherent, connected subgraph prioritizing high-value security context.

    Never creates dangling edges. Ensures returned findings match the selected subgraph.
    """
    if not graph.nodes or (max_nodes is not None and max_nodes <= 0):
        return {"nodes": [], "edges": [], "findings": []}

    # 1. Build adjacency map for fast, deterministic neighbor queries
    adj: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for edge in graph.edges:
        adj[edge.source_id].append((edge.target_id, edge.edge_type))
        adj[edge.target_id].append((edge.source_id, edge.edge_type))

    def get_event_neighbors(ev_id: str) -> list[str]:
        neighbors = []
        for n_id, _ in adj[ev_id]:
            if n_id in graph.nodes:
                neighbors.append(n_id)
        # Deterministic sort according to preferred entity investigation hierarchy
        neighbors.sort(key=lambda nid: (TYPE_ORDER.get(graph.nodes[nid].node_type, 99), nid))
        return neighbors

    # 2. Scope restriction based on parameters
    if employee_id:
        emp_id = f"employee:{employee_id}"
        if emp_id not in graph.nodes:
            return {"nodes": [], "edges": [], "findings": []}
        scope: set[str] = {emp_id}
        emp_events: set[str] = set()
        for target, _ in adj[emp_id]:
            # Do NOT pull in other employees to fill space
            if not target.startswith("employee:") or target == emp_id:
                scope.add(target)
                if target.startswith("event:"):
                    emp_events.add(target)
        for ev in emp_events:
            for target, _ in adj[ev]:
                if not target.startswith("employee:") or target == emp_id:
                    scope.add(target)
        candidate_ids = {nid for nid in scope if nid in graph.nodes}

    elif attack_run_id:
        run_id = f"attack_run:{attack_run_id}"
        if run_id not in graph.nodes:
            return {"nodes": [], "edges": [], "findings": []}
        scope = {run_id}
        for target, _ in adj[run_id]:
            scope.add(target)
        run_events = {nid for nid in scope if nid.startswith("event:")}
        for ev in run_events:
            for target, _ in adj[ev]:
                scope.add(target)
        candidate_ids = {nid for nid in scope if nid in graph.nodes}

    else:
        candidate_ids = set(graph.nodes.keys())

    # Filter findings if severity specified
    findings_pool = list(graph.findings)
    if severity:
        findings_pool = [f for f in findings_pool if f.severity.lower() == severity.lower()]

    # If node_type specified, candidate_ids strictly filtered to that type
    if node_type:
        candidate_ids = {nid for nid in candidate_ids if graph.nodes[nid].node_type == node_type}

    # 3. Selection up to max_nodes
    selected: set[str] = set()

    def try_add(nid: str) -> bool:
        if max_nodes is not None and len(selected) >= max_nodes:
            return False
        if nid in candidate_ids:
            selected.add(nid)
            return True
        return False

    if max_nodes is None or len(candidate_ids) <= max_nodes:
        selected = set(candidate_ids)

    elif employee_id:
        # Prioritize: Employee -> Events (Critical -> High -> Medium -> Low) -> Infrastructure
        emp_id = f"employee:{employee_id}"
        try_add(emp_id)

        emp_events = [graph.nodes[nid] for nid in candidate_ids if graph.nodes[nid].node_type == "event"]
        risk_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        emp_events.sort(key=lambda n: (risk_rank.get(n.metadata.get("risk_level", "Low"), 3), n.node_id))

        for ev in emp_events:
            if len(selected) >= max_nodes:
                break
            if try_add(ev.node_id):
                for nb in get_event_neighbors(ev.node_id):
                    try_add(nb)

        remaining = sorted(candidate_ids - selected, key=lambda nid: (TYPE_ORDER.get(graph.nodes[nid].node_type, 99), nid))
        for nid in remaining:
            if not try_add(nid):
                break

    elif attack_run_id:
        # Prioritize: AttackRun -> linked Events -> Employees -> Devices -> IPs -> Locations -> Files
        run_id = f"attack_run:{attack_run_id}"
        try_add(run_id)

        run_events = [graph.nodes[nid] for nid in candidate_ids if graph.nodes[nid].node_type == "event"]
        run_events.sort(key=lambda n: (
            0 if n.metadata.get("risk_level") in ("Critical", "High") else 1,
            n.node_id
        ))

        for ev in run_events:
            if len(selected) >= max_nodes:
                break
            if try_add(ev.node_id):
                for nb in get_event_neighbors(ev.node_id):
                    try_add(nb)

        remaining = sorted(candidate_ids - selected, key=lambda nid: (TYPE_ORDER.get(graph.nodes[nid].node_type, 99), nid))
        for nid in remaining:
            if not try_add(nid):
                break

    elif node_type:
        def node_rank(nid: str) -> tuple[int, int, str]:
            high_findings = sum(1 for f in findings_pool if nid in f.entities and f.severity in ("critical", "high"))
            edges_count = len(adj[nid])
            return (-high_findings, -edges_count, nid)

        sorted_nodes = sorted(candidate_ids, key=node_rank)
        for nid in sorted_nodes[:max_nodes]:
            selected.add(nid)

    else:
        # General connected subgraph selection
        # Priority 1: Entities involved in High/Critical graph findings
        high_crit_findings = [f for f in findings_pool if f.severity in ("critical", "high")]
        high_crit_findings.sort(key=lambda f: (0 if f.severity == "critical" else 1, f.finding_type, f.entities))

        for f in high_crit_findings:
            if len(selected) >= max_nodes:
                break
            for ent in f.entities:
                try_add(ent)
            for eid in f.supporting_events:
                ev_id = f"event:{eid}"
                if try_add(ev_id):
                    for ep in get_event_neighbors(ev_id):
                        try_add(ep)

        # Priority 2: High/Critical events
        if len(selected) < max_nodes:
            high_crit_evts = [
                n for n in graph.nodes.values()
                if n.node_type == "event" and n.metadata.get("risk_level") in ("Critical", "High")
            ]
            high_crit_evts.sort(key=lambda n: (0 if n.metadata.get("risk_level") == "Critical" else 1, n.node_id))
            for ev in high_crit_evts:
                if len(selected) >= max_nodes:
                    break
                if try_add(ev.node_id):
                    for ep in get_event_neighbors(ev.node_id):
                        try_add(ep)

        # Priority 3: Medium-risk events
        if len(selected) < max_nodes:
            med_evts = [
                n for n in graph.nodes.values()
                if n.node_type == "event" and n.metadata.get("risk_level") == "Medium"
            ]
            med_evts.sort(key=lambda n: n.node_id)
            for ev in med_evts:
                if len(selected) >= max_nodes:
                    break
                if try_add(ev.node_id):
                    for ep in get_event_neighbors(ev.node_id):
                        try_add(ep)

        # Priority 4: Attack Runs
        if len(selected) < max_nodes:
            runs = [n for n in graph.nodes.values() if n.node_type == "attack_run"]
            runs.sort(key=lambda n: n.node_id)
            for r in runs:
                if len(selected) >= max_nodes:
                    break
                if try_add(r.node_id):
                    for target, _ in adj[r.node_id]:
                        try_add(target)

        # Priority 5: Suspicious/shared devices
        if len(selected) < max_nodes:
            dev_nodes = [n for n in graph.nodes.values() if n.node_type == "device"]
            dev_nodes.sort(key=lambda n: (-len(adj[n.node_id]), n.node_id))
            for d in dev_nodes:
                if len(selected) >= max_nodes:
                    break
                try_add(d.node_id)

        # Priority 6: Suspicious/shared IPs
        if len(selected) < max_nodes:
            ip_nodes = [n for n in graph.nodes.values() if n.node_type == "ip_address"]
            ip_nodes.sort(key=lambda n: (-len(adj[n.node_id]), n.node_id))
            for ip in ip_nodes:
                if len(selected) >= max_nodes:
                    break
                try_add(ip.node_id)

        # Priority 7: Sensitive files
        if len(selected) < max_nodes:
            file_nodes = [n for n in graph.nodes.values() if n.node_type == "file"]
            file_nodes.sort(key=lambda n: n.node_id)
            for fn in file_nodes:
                if len(selected) >= max_nodes:
                    break
                try_add(fn.node_id)

        # Priority 8: Related employees & neighbor expansion
        if len(selected) < max_nodes:
            current_selected = sorted(selected, key=lambda nid: (TYPE_ORDER.get(graph.nodes[nid].node_type, 99), nid))
            for nid in current_selected:
                if len(selected) >= max_nodes:
                    break
                for target, _ in adj[nid]:
                    if not try_add(target):
                        break

    # Build final node list
    final_nodes = [
        graph.nodes[nid]
        for nid in sorted(selected, key=lambda n: (TYPE_ORDER.get(graph.nodes[n].node_type, 99), n))
    ]
    final_node_ids = set(selected)

    # Strictly preserve edges whose endpoints are BOTH present
    seen_edges: set[tuple[str, str, str]] = set()
    final_edges: list[GraphEdge] = []
    for e in graph.edges:
        if e.source_id in final_node_ids and e.target_id in final_node_ids:
            key = (e.source_id, e.target_id, e.edge_type)
            if key not in seen_edges:
                seen_edges.add(key)
                final_edges.append(e)

    # Scope findings: a finding is relevant when at least one primary/involved entity
    # is included AND its supporting evidence can be meaningfully represented
    scoped_findings: list[GraphFinding] = []
    for f in findings_pool:
        if not f.entities:
            continue

        ents_in = [e for e in f.entities if e in final_node_ids]
        evts_in = [e for e in f.supporting_events if f"event:{e}" in final_node_ids]
        runs_in = [r for r in f.supporting_attack_runs if f"attack_run:{r}" in final_node_ids]

        # Case 1: Focal entity (f.entities[0]) is present
        if f.entities[0] in final_node_ids:
            if len(evts_in) > 0 or len(runs_in) > 0 or len(ents_in) >= 2 or len(f.entities) == 1:
                scoped_findings.append(f)
        # Case 2: For employee_id filter, if the employee is in f.entities and has visible evidence
        elif employee_id and f"employee:{employee_id}" in f.entities:
            if len(evts_in) > 0 or len(ents_in) >= 2:
                scoped_findings.append(f)
        # Case 3: For attack_run_id filter, if the attack run is in entities or supporting runs
        elif attack_run_id and (f"attack_run:{attack_run_id}" in f.entities or attack_run_id in f.supporting_attack_runs):
            if len(evts_in) > 0 or len(ents_in) >= 1:
                scoped_findings.append(f)

    # Deduplicate findings
    unique_findings: list[GraphFinding] = []
    seen_findings: set[tuple[str, str, tuple[str, ...], tuple[str, ...]]] = set()
    for f in scoped_findings:
        f_key = (f.finding_type, f.severity, f.entities, f.supporting_events)
        if f_key not in seen_findings:
            seen_findings.add(f_key)
            unique_findings.append(f)

    return {
        "nodes": final_nodes,
        "edges": final_edges,
        "findings": unique_findings,
    }
