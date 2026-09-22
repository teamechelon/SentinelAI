"""Application service orchestrating generation, detection, storage, and simulation."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from sentinel_ai import config
from sentinel_ai.baselines import build_behavioural_assessment, build_profiles
from sentinel_ai.demo import build_attack_sequence, build_scenario_event, generate_dataset
from sentinel_ai.detection import analyze_sequences, combine_risk, evaluate_rules
from sentinel_ai.domain import (
    ActivityEvent,
    Alert,
    BehaviouralAssessment,
    BehaviourProfile,
    DetectionResult,
    Employee,
    FeatureVector,
    SimulationRun,
)
from sentinel_ai.features import build_feature_vector
from sentinel_ai.graph import SecurityGraph, analyze_graph, build_security_graph
from sentinel_ai.models import IsolationForestDetector
from sentinel_ai.storage import SentinelDatabase


class SentinelService:
    def __init__(self, database_path: str | Path = config.DEFAULT_DATABASE_PATH) -> None:
        self.database = SentinelDatabase(database_path)
        self.detector = IsolationForestDetector()

    @property
    def model_status(self) -> str:
        return self.detector.status

    def initialize(self, reseed: bool = False) -> None:
        self.database.initialize()
        if reseed or self.database.is_empty():
            self.reseed()
        else:
            self._train_from_database()

    def reseed(self) -> None:
        employees, events = generate_dataset()
        self.database.clear_all()
        self.database.insert_employees(employees)
        self.database.insert_events(events)

        grouped_normal: dict[str, list[ActivityEvent]] = defaultdict(list)
        for event in events:
            if event.scenario == "normal" and not event.is_suspicious:
                grouped_normal[event.employee_id].append(event)

        baseline_events: list[ActivityEvent] = []
        training_event_ids: set[str] = set()
        for employee in employees:
            employee_events = sorted(grouped_normal[employee.employee_id], key=lambda item: item.timestamp)
            split_index = max(1, int(len(employee_events) * 0.7))
            baseline_events.extend(employee_events[:split_index])
            training_event_ids.update(event.event_id for event in employee_events[split_index:])

        profiles = build_profiles(employees, baseline_events)
        self.database.upsert_profiles(list(profiles.values()))
        training_features = self._feature_sequence(events, profiles, training_event_ids)
        self.detector.fit(training_features)
        self._detect_seed_events(events, profiles, employees)

    def _train_from_database(self) -> None:
        events = self.database.list_activity_events()
        profiles = self.database.list_profiles()
        grouped_normal: dict[str, list[ActivityEvent]] = defaultdict(list)
        for event in events:
            if event.scenario == "normal" and not event.is_suspicious:
                grouped_normal[event.employee_id].append(event)
        training_ids: set[str] = set()
        for employee_events in grouped_normal.values():
            ordered = sorted(employee_events, key=lambda item: item.timestamp)
            split_index = max(1, int(len(ordered) * 0.7))
            training_ids.update(event.event_id for event in ordered[split_index:])
        self.detector.fit(self._feature_sequence(events, profiles, training_ids))

    @staticmethod
    def _feature_sequence(
        events: list[ActivityEvent],
        profiles: dict[str, BehaviourProfile],
        selected_event_ids: set[str],
    ) -> list[FeatureVector]:
        previous_login: dict[str, ActivityEvent] = {}
        features: list[FeatureVector] = []
        for event in sorted(events, key=lambda item: (item.timestamp, item.event_id)):
            profile = profiles.get(event.employee_id)
            if not profile:
                continue
            vector = build_feature_vector(event, profile, previous_login.get(event.employee_id))
            if event.event_id in selected_event_ids:
                features.append(vector)
            if event.activity_type == "login" and event.login_success:
                previous_login[event.employee_id] = event
        return features

    def _detect_seed_events(
        self,
        events: list[ActivityEvent],
        profiles: dict[str, BehaviourProfile],
        employees: list[Employee],
    ) -> None:
        previous_login: dict[str, ActivityEvent] = {}
        assessment_history: list[ActivityEvent] = []
        employees_by_id = {employee.employee_id: employee for employee in employees}
        for event in sorted(events, key=lambda item: (item.timestamp, item.event_id)):
            profile = profiles[event.employee_id]
            assessment = build_behavioural_assessment(
                event,
                employees_by_id[event.employee_id],
                employees,
                assessment_history,
            )
            result = self._evaluate(event, profile, previous_login.get(event.employee_id), assessment)
            self._persist_result(event, result)
            assessment_history.append(event)
            if event.activity_type == "login" and event.login_success:
                previous_login[event.employee_id] = event

    def _evaluate(
        self,
        event: ActivityEvent,
        profile: BehaviourProfile,
        previous_login: ActivityEvent | None,
        assessment: BehaviouralAssessment | None = None,
    ) -> DetectionResult:
        features = build_feature_vector(event, profile, previous_login)
        rules = evaluate_rules(event, profile, features)
        model_score = self.detector.score(features)
        result = combine_risk(event, features, rules, model_score)
        return replace(result, behavioural_assessment=assessment)

    def _persist_result(self, event: ActivityEvent, result: DetectionResult) -> None:
        self.database.insert_detection(result)
        if result.final_risk_score >= config.ALERT_MINIMUM_SCORE:
            title = result.triggered_rules[0].rule_name.replace("_", " ").title() if result.triggered_rules else "Behavioral Anomaly"
            self.database.create_alert(
                Alert(
                    alert_id=f"ALT-{event.event_id}",
                    detection_id=result.detection_id,
                    event_id=event.event_id,
                    employee_id=event.employee_id,
                    created_at=result.detected_at,
                    status="New",
                    title=title,
                    risk_score=result.final_risk_score,
                    risk_level=result.risk_level,
                )
            )

    def detect_and_persist(self, event: ActivityEvent) -> DetectionResult:
        employee = self.database.get_employee(event.employee_id)
        if employee is None:
            raise KeyError(f"Unknown employee: {event.employee_id}")
        profile = self.database.get_profile(event.employee_id)
        if profile is None:
            profile = build_profiles([employee], [])[employee.employee_id]
            self.database.upsert_profiles([profile])
        previous_login = self.database.previous_successful_login(event.employee_id, event.timestamp)
        assessment = build_behavioural_assessment(
            event,
            employee,
            self.database.list_employees(),
            self.database.list_activity_events(),
        )
        self.database.insert_events([event])
        result = self._evaluate(event, profile, previous_login, assessment)
        self._persist_result(event, result)
        return result

    def behavioural_assessment(self, event_id: str) -> BehaviouralAssessment:
        """Recompute structured personal/peer evidence for a persisted event."""

        event = self.database.get_event(event_id)
        if event is None:
            raise KeyError(f"Unknown event: {event_id}")
        employee = self.database.get_employee(event.employee_id)
        if employee is None:
            raise KeyError(f"Unknown employee: {event.employee_id}")
        return build_behavioural_assessment(
            event,
            employee,
            self.database.list_employees(),
            self.database.list_activity_events(),
        )

    def simulate(
        self,
        scenario: str,
        employee_id: str,
        now: datetime | None = None,
    ) -> DetectionResult:
        employee = self.database.get_employee(employee_id)
        if employee is None:
            raise KeyError(f"Unknown employee: {employee_id}")
        timestamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
        event_id = f"SIM-{uuid4().hex[:12].upper()}"
        event = build_scenario_event(employee, scenario, timestamp, event_id)

        if scenario in {"impossible_travel", "combined_account_compromise", "legitimate_travel"}:
            elapsed = timedelta(hours=12 if scenario == "legitimate_travel" else 1)
            anchor_time = event.timestamp - elapsed
            anchor = build_scenario_event(employee, "normal_login", anchor_time, f"{event_id}-ANCHOR")
            anchor = replace(anchor, timestamp=anchor_time)
            self.detect_and_persist(anchor)

        return self.detect_and_persist(event)

    def run_attack_lab(
        self,
        scenario: str,
        employee_id: str,
        start_time: datetime,
        intensity: str = "standard",
    ) -> SimulationRun:
        employee = self.database.get_employee(employee_id)
        if employee is None:
            raise KeyError(f"Unknown employee: {employee_id}")
        timestamp = start_time.astimezone(timezone.utc).replace(microsecond=0)
        simulation_id = f"RUN-{uuid4().hex[:12].upper()}"
        events = build_attack_sequence(employee, scenario, timestamp, simulation_id, intensity)
        self.database.create_simulation_run(simulation_id, employee_id, scenario, timestamp, intensity)
        try:
            for index, event in enumerate(events):
                self.detect_and_persist(event)
                self.database.link_simulation_event(simulation_id, event.event_id, index)
            self.database.update_simulation_status(simulation_id, "complete")
        except Exception:
            self.database.update_simulation_status(simulation_id, "failed")
            raise
        return SimulationRun(
            simulation_id=simulation_id,
            employee_id=employee_id,
            scenario=scenario,
            start_time=timestamp,
            intensity=intensity,
            status="complete",
            created_at=datetime.now(timezone.utc),
            event_ids=tuple(event.event_id for event in events),
            findings=analyze_sequences(events),
        )

    def simulation_run(self, simulation_id: str) -> SimulationRun:
        row = self.database.get_simulation_run(simulation_id)
        if row is None:
            raise KeyError(f"Unknown simulation: {simulation_id}")
        events = [self.database.get_event(event_id) for event_id in row["event_ids"]]
        available = [event for event in events if event is not None]
        return SimulationRun(
            simulation_id=str(row["simulation_id"]),
            employee_id=str(row["employee_id"]),
            scenario=str(row["scenario"]),
            start_time=datetime.fromisoformat(str(row["start_time"])),
            intensity=str(row["intensity"]),
            status=str(row["status"]),
            created_at=datetime.fromisoformat(str(row["created_at"])),
            event_ids=tuple(str(event_id) for event_id in row["event_ids"]),
            findings=analyze_sequences(available),
        )

    def update_alert_status(self, alert_id: str, status: str) -> None:
        self.database.update_alert_status(alert_id, status)

    def add_investigation_note(self, alert_id: str, note: str) -> int:
        return self.database.add_investigation_note(alert_id, note)

    def employees(self) -> list[Employee]:
        return self.database.list_employees()

    def event_rows(self) -> list[dict[str, object]]:
        return self.database.list_event_rows()

    def detection_rows(self, employee_id: str | None = None) -> list[dict[str, object]]:
        return self.database.list_detection_rows(employee_id)

    def alert_rows(self) -> list[dict[str, object]]:
        return self.database.list_alert_rows()

    def build_graph(self) -> SecurityGraph:
        """Build security graph from current database state."""
        employees = self.employees()
        events = self.database.list_activity_events()
        detection_rows = self.detection_rows()
        simulation_runs = self._list_simulation_runs()
        graph = build_security_graph(employees, events, detection_rows, simulation_runs)
        findings = analyze_graph(graph, events, detection_rows, config)
        graph.findings = findings
        return graph

    def _list_simulation_runs(self) -> list[dict]:
        """List all simulation runs from database."""
        return self.database.list_simulation_runs()

    def graph_overview(self) -> dict:
        graph = self.build_graph()
        entity_counts = {}
        for node_type in ["employee", "event", "device", "ip_address", "location", "file", "department", "attack_run"]:
            entity_counts[node_type] = len(graph.nodes_by_type(node_type))
        high_severity = sum(1 for f in graph.findings if f.severity in ("high", "critical"))
        return {
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
            "entity_counts": entity_counts,
            "finding_count": len(graph.findings),
            "high_severity_finding_count": high_severity,
        }


    def graph_entity_detail(self, entity_type: str, entity_id: str) -> dict | None:
        graph = self.build_graph()
        full_id = f"{entity_type}:{entity_id}"
        node = graph.nodes.get(full_id)
        if not node:
            return None
        neighbors = graph.neighbors(full_id)
        edges = graph.edges_for(full_id)
        findings = graph.findings_for(full_id)
        # Get related event IDs from edges
        event_ids = set()
        for edge in edges:
            if "event_id" in edge.metadata:
                event_ids.add(edge.metadata["event_id"])
        return {
            "entity": node,
            "connected_entities": neighbors,
            "edges": edges,
            "findings": findings,
            "event_ids": sorted(event_ids),
        }

    def graph_event_context(self, event_id: str) -> dict | None:
        event = self.database.get_event(event_id)
        if not event:
            return None
        graph = self.build_graph()
        # Find all nodes connected to this event
        related_nodes = []
        related_findings = []
        for edge in graph.edges:
            if edge.metadata.get("event_id") == event_id:
                for nid in [edge.source_id, edge.target_id]:
                    if nid in graph.nodes:
                        related_nodes.append(graph.nodes[nid])
        # Deduplicate
        seen = set()
        unique_nodes = []
        for n in related_nodes:
            if n.node_id not in seen:
                seen.add(n.node_id)
                unique_nodes.append(n)
        # Findings mentioning this event
        for f in graph.findings:
            if event_id in f.supporting_events:
                related_findings.append(f)
        return {
            "event_id": event_id,
            "entities": unique_nodes,
            "findings": related_findings,
        }

    def graph_attack_run_context(self, simulation_id: str) -> dict | None:
        run_data = self.database.get_simulation_run(simulation_id)
        if not run_data:
            return None
        graph = self.build_graph()
        run_node_id = f"attack_run:{simulation_id}"
        # Get all connected entities
        neighbors = graph.neighbors(run_node_id)
        findings = graph.findings_for(run_node_id)
        # Also find findings for all events in the run
        event_ids = run_data.get("event_ids", [])
        for eid in event_ids:
            for f in graph.findings:
                if eid in f.supporting_events and f not in findings:
                    findings.append(f)
        # Categorize neighbors
        result = {
            "simulation_id": simulation_id,
            "employees": [n for n in neighbors if n.node_type == "employee"],
            "devices": [n for n in neighbors if n.node_type == "device"],
            "ip_addresses": [n for n in neighbors if n.node_type == "ip_address"],
            "locations": [n for n in neighbors if n.node_type == "location"],
            "files": [n for n in neighbors if n.node_type == "file"],
            "findings": findings,
            "event_ids": event_ids,
        }
        return result

    def graph_findings(self, severity=None, finding_type=None, entity_type=None, employee_id=None) -> list:
        graph = self.build_graph()
        results = list(graph.findings)
        if severity:
            results = [f for f in results if f.severity == severity]
        if finding_type:
            results = [f for f in results if f.finding_type == finding_type]
        if employee_id:
            emp_id = f"employee:{employee_id}"
            results = [f for f in results if emp_id in f.entities]
        if entity_type:
            results = [f for f in results if any(e.startswith(f"{entity_type}:") for e in f.entities)]
        return results

    def graph_data(
        self,
        node_type: str | None = None,
        severity: str | None = None,
        employee_id: str | None = None,
        attack_run_id: str | None = None,
        max_nodes: int | None = None,
    ) -> dict:
        graph = self.build_graph()
        nodes = list(graph.nodes.values())
        edges = list(graph.edges)
        findings = list(graph.findings)

        if node_type:
            nodes = [n for n in nodes if n.node_type == node_type]
            node_ids = {n.node_id for n in nodes}
            edges = [e for e in edges if e.source_id in node_ids or e.target_id in node_ids]

        if severity:
            findings = [f for f in findings if f.severity == severity]

        if employee_id:
            emp_node_id = f"employee:{employee_id}"
            nodes = [n for n in nodes if n.node_id == emp_node_id or emp_node_id in [e.source_id for e in edges if e.target_id == n.node_id] or emp_node_id in [e.target_id for e in edges if e.source_id == n.node_id]]
            node_ids = {n.node_id for n in nodes}
            edges = [e for e in edges if e.source_id in node_ids and e.target_id in node_ids]
            findings = [f for f in findings if emp_node_id in f.entities]

        if attack_run_id:
            run_node_id = f"attack_run:{attack_run_id}"
            run_edges = [e for e in edges if e.source_id == run_node_id or e.target_id == run_node_id]
            node_ids = {run_node_id}
            for e in run_edges:
                node_ids.add(e.source_id)
                node_ids.add(e.target_id)
            nodes = [n for n in nodes if n.node_id in node_ids]
            edges = [e for e in edges if e.source_id in node_ids and e.target_id in node_ids]
            findings = [f for f in findings if run_node_id in f.entities or any(eid in f.supporting_events for eid in [e.metadata.get("event_id") for e in edges if e.metadata.get("event_id")])]

        if max_nodes and len(nodes) > max_nodes:
            nodes.sort(key=lambda n: (0 if n.node_type != "event" else 1, n.node_id))
            nodes = nodes[:max_nodes]

        # Strict safety check: never return an edge whose source or target node is missing
        node_ids = {n.node_id for n in nodes}
        edges = [e for e in edges if e.source_id in node_ids and e.target_id in node_ids]

        return {
            "nodes": nodes,
            "edges": edges,
            "findings": findings,
        }

