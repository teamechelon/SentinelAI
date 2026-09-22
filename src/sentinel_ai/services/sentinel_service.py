"""Application service orchestrating generation, detection, storage, and simulation."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from sentinel_ai import config
from sentinel_ai.baselines import build_profiles
from sentinel_ai.demo import build_scenario_event, generate_dataset
from sentinel_ai.detection import combine_risk, evaluate_rules
from sentinel_ai.domain import ActivityEvent, Alert, BehaviourProfile, DetectionResult, Employee, FeatureVector
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
        self._detect_seed_events(events, profiles)

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

    def _detect_seed_events(self, events: list[ActivityEvent], profiles: dict[str, BehaviourProfile]) -> None:
        previous_login: dict[str, ActivityEvent] = {}
        for event in sorted(events, key=lambda item: (item.timestamp, item.event_id)):
            profile = profiles[event.employee_id]
            result = self._evaluate(event, profile, previous_login.get(event.employee_id))
            self._persist_result(event, result)
            if event.activity_type == "login" and event.login_success:
                previous_login[event.employee_id] = event

    def _evaluate(
        self,
        event: ActivityEvent,
        profile: BehaviourProfile,
        previous_login: ActivityEvent | None,
    ) -> DetectionResult:
        features = build_feature_vector(event, profile, previous_login)
        rules = evaluate_rules(event, profile, features)
        model_score = self.detector.score(features)
        return combine_risk(event, features, rules, model_score)

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
        profile = self.database.get_profile(event.employee_id)
        if profile is None:
            employee = self.database.get_employee(event.employee_id)
            if employee is None:
                raise KeyError(f"Unknown employee: {event.employee_id}")
            profile = build_profiles([employee], [])[employee.employee_id]
            self.database.upsert_profiles([profile])
        previous_login = self.database.previous_successful_login(event.employee_id, event.timestamp)
        self.database.insert_events([event])
        result = self._evaluate(event, profile, previous_login)
        self._persist_result(event, result)
        return result

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

