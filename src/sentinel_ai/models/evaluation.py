"""Deterministic, leakage-safe evaluation for existing detection channels."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from sentinel_ai.baselines import build_profiles
from sentinel_ai.demo import generate_dataset
from sentinel_ai.detection import evaluate_rules
from sentinel_ai.domain import ActivityEvent, BehaviourProfile, Employee, FeatureVector
from sentinel_ai.features import build_feature_vector
from sentinel_ai.models.isolation_forest import IsolationForestDetector


@dataclass(frozen=True)
class EvaluationDataset:
    employees: tuple[Employee, ...]
    all_events: tuple[ActivityEvent, ...]
    profiles: dict[str, BehaviourProfile]
    training: tuple[tuple[ActivityEvent, FeatureVector], ...]
    normal_test: tuple[tuple[ActivityEvent, FeatureVector], ...]
    anomaly_test: tuple[tuple[ActivityEvent, FeatureVector], ...]
    split: dict[str, Any]


def prepare_evaluation_dataset() -> EvaluationDataset:
    employees, events = generate_dataset()
    normal_by_employee: dict[str, list[ActivityEvent]] = defaultdict(list)
    for event in events:
        if event.scenario == "normal" and not event.is_suspicious:
            normal_by_employee[event.employee_id].append(event)
    baseline: list[ActivityEvent] = []
    training_ids: set[str] = set()
    normal_test_ids: set[str] = set()
    for employee in employees:
        ordered = sorted(normal_by_employee[employee.employee_id], key=lambda item: (item.timestamp, item.event_id))
        baseline_end = int(len(ordered) * 0.6)
        training_end = int(len(ordered) * 0.8)
        baseline.extend(ordered[:baseline_end])
        training_ids.update(item.event_id for item in ordered[baseline_end:training_end])
        normal_test_ids.update(item.event_id for item in ordered[training_end:])
    anomaly_ids = {event.event_id for event in events if event.is_suspicious}
    selected = training_ids | normal_test_ids | anomaly_ids
    profiles = build_profiles(employees, baseline)
    features: dict[str, FeatureVector] = {}
    previous_login: dict[str, ActivityEvent] = {}
    for event in sorted(events, key=lambda item: (item.timestamp, item.event_id)):
        if event.event_id in selected:
            features[event.event_id] = build_feature_vector(event, profiles[event.employee_id], previous_login.get(event.employee_id))
        if event.activity_type == "login" and event.login_success:
            previous_login[event.employee_id] = event
    lookup = {event.event_id: event for event in events}

    def pairs(ids: set[str]) -> tuple[tuple[ActivityEvent, FeatureVector], ...]:
        return tuple((lookup[event_id], features[event_id]) for event_id in sorted(ids, key=lambda event_id: (lookup[event_id].timestamp, event_id)))

    return EvaluationDataset(
        employees=tuple(employees), all_events=tuple(events), profiles=profiles,
        training=pairs(training_ids), normal_test=pairs(normal_test_ids), anomaly_test=pairs(anomaly_ids),
        split={
            "strategy": "Per-employee chronological 60/20/20 split on normal history; suspicious events are evaluation-only.",
            "baselineRows": len(baseline), "trainingRows": len(training_ids), "normalTestRows": len(normal_test_ids), "anomalyTestRows": len(anomaly_ids),
            "futureDataUsed": False,
        },
    )


def classification_metrics(labels: list[bool], predictions: list[bool]) -> dict[str, float | int]:
    tp = sum(label and prediction for label, prediction in zip(labels, predictions, strict=True))
    fp = sum(not label and prediction for label, prediction in zip(labels, predictions, strict=True))
    fn = sum(label and not prediction for label, prediction in zip(labels, predictions, strict=True))
    tn = sum(not label and not prediction for label, prediction in zip(labels, predictions, strict=True))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0
    return {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4), "falsePositiveRate": round(false_positive_rate, 4), "truePositive": tp, "falsePositive": fp, "trueNegative": tn, "falseNegative": fn}


def _coverage(events: list[ActivityEvent], predictions: list[bool]) -> dict[str, dict[str, float | int]]:
    counts: dict[str, list[bool]] = defaultdict(list)
    for event, prediction in zip(events, predictions, strict=True):
        if event.is_suspicious:
            counts[event.scenario].append(prediction)
    return {scenario: {"detected": sum(values), "total": len(values), "recall": round(sum(values) / len(values), 4)} for scenario, values in sorted(counts.items())}


@lru_cache(maxsize=1)
def evaluate_existing_models() -> dict[str, Any]:
    dataset = prepare_evaluation_dataset()
    detector = IsolationForestDetector()
    detector.fit([features for _, features in dataset.training])
    evaluation = list(dataset.normal_test) + list(dataset.anomaly_test)
    labels = [event.is_suspicious for event, _ in evaluation]
    classical_scores = [detector.score(features).anomaly_percentile for _, features in evaluation]
    classical_predictions = [score is not None and score >= 95.0 for score in classical_scores]
    rule_predictions = [bool(evaluate_rules(event, dataset.profiles[event.employee_id], features)) for event, features in evaluation]
    events = [event for event, _ in evaluation]
    return {
        "dataset": dataset.split,
        "thresholds": {"classical": "Persisted nonconformity percentile >= 95", "rules": "One or more existing deterministic rules fired"},
        "classical": {"name": "Isolation Forest", "status": detector.status, "metrics": classification_metrics(labels, classical_predictions), "scenarioCoverage": _coverage(events, classical_predictions)},
        "rules": {"name": "Deterministic rules", "status": "ready", "metrics": classification_metrics(labels, rule_predictions), "scenarioCoverage": _coverage(events, rule_predictions)},
        "limitations": [
            "Synthetic deterministic data is used; results do not establish production effectiveness.",
            "Suspicious scenarios are generated patterns, not independently collected ground truth.",
            "Classical threshold is a training-history percentile, not an attack probability.",
        ],
    }
