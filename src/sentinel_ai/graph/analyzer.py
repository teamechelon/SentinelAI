from collections import defaultdict
from datetime import datetime, timezone
from sentinel_ai.graph.models import SecurityGraph, GraphFinding
from sentinel_ai.domain import ActivityEvent

def _severity_for_events(risk_levels: list[str]) -> str:
    if "Critical" in risk_levels or "High" in risk_levels:
        return "high"
    if "Medium" in risk_levels:
        return "medium"
    return "informational"

def analyze_graph(graph: SecurityGraph, events: list[ActivityEvent], detection_rows: list[dict], config_module) -> list[GraphFinding]:
    findings = []
    
    event_risk_scores = {row["event_id"]: row.get("final_risk_score", 0.0) for row in detection_rows}
    event_risk_levels = {row["event_id"]: row.get("risk_level", "Low") for row in detection_rows}
    event_timestamps = {e.event_id: e.timestamp for e in events}
    
    trusted_ips = getattr(config_module, "TRUSTED_CORPORATE_IPS", set())
    trusted_devices = getattr(config_module, "TRUSTED_COMMON_DEVICES", set())

    # A. SHARED_DEVICE
    for dev in graph.nodes_by_type("device"):
        edges = [e for e in graph.edges if e.target_id == dev.node_id and e.edge_type in ("USES_DEVICE", "USED_DEVICE")]
        employees = list({e.source_id for e in edges if e.source_id.startswith("employee:")})
        if len(employees) >= config_module.GRAPH_SHARED_DEVICE_MIN_EMPLOYEES:
            suspicious_edges = [e for e in edges if event_risk_scores.get(e.metadata.get("event_id"), 0) >= 30]
            
            is_trusted = dev.label in trusted_devices
            
            if suspicious_edges:
                risk_levels = [e.metadata.get("risk_level", "Low") for e in suspicious_edges]
                high_critical_count = len([rl for rl in risk_levels if rl in ("High", "Critical")])
                
                if high_critical_count >= 1 and not is_trusted:
                    severity = "high"
                elif "Medium" in risk_levels:
                    severity = "medium"
                else:
                    severity = "low" if not is_trusted else "informational"
                
                supporting_events = tuple(e.metadata.get("event_id") for e in suspicious_edges if e.metadata.get("event_id"))
                findings.append(GraphFinding(
                    finding_type="SHARED_DEVICE",
                    severity=severity,
                    entities=tuple([dev.node_id] + employees),
                    supporting_events=supporting_events,
                    supporting_attack_runs=(),
                    observed_relationship=f"Device shared by {len(employees)} employees in suspicious contexts",
                    explanation=f"Device {dev.label} is used by multiple employees and is associated with medium+ risk events."
                ))
            elif is_trusted or len(employees) > 5:
                # Common or trusted shared device used normally
                supporting_events = tuple(e.metadata.get("event_id") for e in edges[:5] if e.metadata.get("event_id"))
                findings.append(GraphFinding(
                    finding_type="SHARED_DEVICE",
                    severity="informational",
                    entities=tuple([dev.node_id] + employees),
                    supporting_events=supporting_events,
                    supporting_attack_runs=(),
                    observed_relationship=f"Known shared or corporate device used by {len(employees)} employees",
                    explanation=f"Device {dev.label} is a common shared corporate asset used normally across employees."
                ))

    # B. SHARED_IP
    for ip in graph.nodes_by_type("ip_address"):
        edges = [e for e in graph.edges if e.target_id == ip.node_id and e.edge_type in ("CONNECTS_FROM", "CONNECTED_FROM")]
        employees = list({e.source_id for e in edges if e.source_id.startswith("employee:")})
        if len(employees) >= config_module.GRAPH_SHARED_IP_MIN_EMPLOYEES:
            suspicious_edges = [e for e in edges if event_risk_scores.get(e.metadata.get("event_id"), 0) >= 60]
            is_trusted = ip.label in trusted_ips
            
            if suspicious_edges and not is_trusted:
                high_critical_count = len([e for e in suspicious_edges if e.metadata.get("risk_level") in ("High", "Critical")])
                if high_critical_count >= 3:
                    severity = "critical"
                elif high_critical_count > 0:
                    severity = "high"
                else:
                    medium_count = len([e for e in edges if event_risk_scores.get(e.metadata.get("event_id"), 0) >= 30])
                    severity = "medium" if medium_count > 1 else "low"
                    
                supporting_events = tuple(e.metadata.get("event_id") for e in suspicious_edges if e.metadata.get("event_id"))
                findings.append(GraphFinding(
                    finding_type="SHARED_IP",
                    severity=severity,
                    entities=tuple([ip.node_id] + employees),
                    supporting_events=supporting_events,
                    supporting_attack_runs=(),
                    observed_relationship=f"IP address shared by {len(employees)} employees",
                    explanation=f"IP {ip.label} is used by multiple employees with high-risk events."
                ))
            else:
                # Normal sharing or trusted corporate NAT/VPN gateway -> Informational / Low
                supporting_events = tuple(e.metadata.get("event_id") for e in edges[:5] if e.metadata.get("event_id"))
                findings.append(GraphFinding(
                    finding_type="SHARED_IP",
                    severity="informational",
                    entities=tuple([ip.node_id] + employees),
                    supporting_events=supporting_events,
                    supporting_attack_runs=(),
                    observed_relationship=f"Common corporate gateway or IP shared by {len(employees)} employees",
                    explanation=f"IP {ip.label} is a common network gateway used normally by multiple employees."
                ))

    # C. MULTI_USER_SUSPICIOUS_INFRASTRUCTURE
    for dev in graph.nodes_by_type("device"):
        edges = [e for e in graph.edges if e.target_id == dev.node_id and e.edge_type in ("USES_DEVICE", "USED_DEVICE")]
        if not edges: continue
        
        dev_event_ids = {e.metadata.get("event_id") for e in edges if e.metadata.get("event_id")}
        for ip in graph.nodes_by_type("ip_address"):
            ip_edges = [e for e in graph.edges if e.target_id == ip.node_id and e.edge_type in ("CONNECTS_FROM", "CONNECTED_FROM")]
            ip_event_ids = {e.metadata.get("event_id") for e in ip_edges if e.metadata.get("event_id")}
            
            common_events = dev_event_ids.intersection(ip_event_ids)
            emp_to_events = defaultdict(list)
            for eid in common_events:
                risk = event_risk_scores.get(eid, 0)
                if risk >= 60:
                    emp_id = next((e.source_id for e in edges if e.metadata.get("event_id") == eid and e.source_id.startswith("employee:")), None)
                    if emp_id:
                        emp_to_events[emp_id].append(eid)
                        
            if len(emp_to_events) >= 2:
                all_suspicious_eids = [eid for events in emp_to_events.values() for eid in events]
                timestamps = [event_timestamps[eid] for eid in all_suspicious_eids if eid in event_timestamps]
                if timestamps:
                    min_t = min(timestamps)
                    max_t = max(timestamps)
                    if (max_t - min_t).total_seconds() / 60 <= config_module.GRAPH_SHARED_ENTITY_WINDOW_MINUTES:
                        levels = [event_risk_levels.get(eid, "Low") for eid in all_suspicious_eids]
                        severity = "critical" if "Critical" in levels else "high"
                        findings.append(GraphFinding(
                            finding_type="MULTI_USER_SUSPICIOUS_INFRASTRUCTURE",
                            severity=severity,
                            entities=tuple([dev.node_id, ip.node_id] + list(emp_to_events.keys())),
                            supporting_events=tuple(all_suspicious_eids),
                            supporting_attack_runs=(),
                            observed_relationship="Same device and IP used by multiple employees rapidly",
                            explanation=f"Device {dev.label} and IP {ip.label} used by multiple users in high-risk events within a short window."
                        ))

    # D. SENSITIVE_FILE_CONVERGENCE
    for fnode in graph.nodes_by_type("file"):
        edges = [e for e in graph.edges if e.target_id == fnode.node_id and e.edge_type in ("ACCESSES_FILE", "ACCESSED_FILE")]
        emp_to_events = defaultdict(list)
        for e in edges:
            eid = e.metadata.get("event_id")
            if eid and eid in event_timestamps:
                src = e.source_id if e.source_id.startswith("employee:") else next((ev.employee_id for ev in events if ev.event_id == eid), e.source_id)
                emp_to_events[src].append(eid)
                
        if len(emp_to_events) >= 2:
            all_eids = [eid for events in emp_to_events.values() for eid in events]
            timestamps = [event_timestamps[eid] for eid in all_eids if eid in event_timestamps]
            if timestamps:
                min_t = min(timestamps)
                max_t = max(timestamps)
                if (max_t - min_t).total_seconds() / 60 <= config_module.GRAPH_FILE_CONVERGENCE_WINDOW_MINUTES:
                    severity = "high" if len(emp_to_events) >= 3 else "medium"
                    findings.append(GraphFinding(
                        finding_type="SENSITIVE_FILE_CONVERGENCE",
                        severity=severity,
                        entities=tuple([fnode.node_id] + list(emp_to_events.keys())),
                        supporting_events=tuple(all_eids),
                        supporting_attack_runs=(),
                        observed_relationship=f"File accessed by {len(emp_to_events)} employees",
                        explanation=f"Sensitive file {fnode.label} accessed by multiple users in a short window."
                    ))

    # E. ATTACK_INFRASTRUCTURE_CLUSTER
    for run in graph.nodes_by_type("attack_run"):
        run_edges = [e for e in graph.edges if e.target_id == run.node_id and e.edge_type == "PART_OF_ATTACK_RUN"]
        infra_nodes = {e.source_id for e in run_edges if not e.source_id.startswith("event:")}
        
        other_suspicious = set()
        for inode in infra_nodes:
            i_edges = [e for e in graph.edges if e.target_id == inode and e.edge_type in ("USES_DEVICE", "USED_DEVICE", "CONNECTS_FROM", "CONNECTED_FROM")]
            for ie in i_edges:
                eid = ie.metadata.get("event_id")
                if eid and eid not in [re.metadata.get("event_id") for re in run_edges]:
                    if event_risk_scores.get(eid, 0) >= 30:
                        other_suspicious.add(eid)
                        
        if other_suspicious:
            findings.append(GraphFinding(
                finding_type="ATTACK_INFRASTRUCTURE_CLUSTER",
                severity="high",
                entities=tuple([run.node_id] + list(infra_nodes)),
                supporting_events=tuple(other_suspicious),
                supporting_attack_runs=(run.node_id,),
                observed_relationship="Attack infrastructure reused",
                explanation=f"Infrastructure from attack run is associated with other suspicious events."
            ))

    # F. HIGH_RISK_ENTITY
    for node_type in ("device", "ip_address", "file"):
        for node in graph.nodes_by_type(node_type):
            if node_type == "device":
                node_events = [e for e in events if e.device_id == node.label]
            elif node_type == "ip_address":
                node_events = [e for e in events if e.ip_address == node.label]
            else:
                node_events = [e for e in events if e.file_name == node.label and e.file_sensitivity in ("Confidential", "Restricted")]
                
            if len(node_events) >= 3:
                eids = [e.event_id for e in node_events]
                high_risk = [eid for eid in eids if event_risk_levels.get(eid) in ("High", "Critical")]
                ratio = len(high_risk) / len(eids)
                if ratio >= config_module.GRAPH_HIGH_RISK_EVENT_RATIO_THRESHOLD:
                    severity = "critical" if ratio >= 0.8 else "high"
                    findings.append(GraphFinding(
                        finding_type="HIGH_RISK_ENTITY",
                        severity=severity,
                        entities=(node.node_id,),
                        supporting_events=tuple(high_risk),
                        supporting_attack_runs=(),
                        observed_relationship="High proportion of risky events",
                        explanation=f"Entity {node.label} has a high ratio of high/critical risk events."
                    ))

    return findings
