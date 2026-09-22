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

