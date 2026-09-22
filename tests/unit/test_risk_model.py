"""Hybrid risk arithmetic and Isolation Forest contracts."""

from dataclasses import replace

import pytest

from sentinel_ai import config
from sentinel_ai.detection import combine_risk, risk_level
from sentinel_ai.domain import FeatureVector, ModelScore, RuleHit
from sentinel_ai.features import build_feature_vector, feature_row
from sentinel_ai.models import IsolationForestDetector


@pytest.mark.parametrize(
    ("score", "expected"),
    [(0, "Low"), (29.99, "Low"), (30, "Medium"), (59.99, "Medium"), (60, "High"), (79.99, "High"), (80, "Critical"), (100, "Critical")],
)
def test_risk_band_boundaries(score, expected) -> None:
    assert risk_level(score) == expected


def test_combined_score_is_capped_and_traceable(normal_event, profile) -> None:
    features = build_feature_vector(normal_event, profile)
    hits = tuple(
        RuleHit(name, 30.0, f"reason {name}", "observed", "expected")
        for name in ("ONE", "TWO", "THREE", "FOUR", "FIVE")
    )
    model = ModelScore("ready", 0.7, 100.0, 25.0, "test", "test")
    result = combine_risk(normal_event, features, hits, model)

    assert result.final_risk_score == 100
    assert result.risk_level == "Critical"
    assert result.rule_contribution == 150
    assert "Final score: 100.00/100" in result.explanation


def test_no_rules_and_unavailable_model_produces_low_explainable_result(normal_event, profile) -> None:
    features = build_feature_vector(normal_event, profile)
    model = ModelScore("untrained", None, None, 0.0, "test", "unavailable")
    result = combine_risk(normal_event, features, (), model)

    assert result.final_risk_score == 0
    assert result.risk_level == "Low"
    assert "No deterministic threat rule fired" in result.explanation
    assert "untrained" in result.explanation


def test_model_exposes_insufficient_training_status(normal_event, profile) -> None:
    detector = IsolationForestDetector()
    vector = build_feature_vector(normal_event, profile)

    assert detector.fit([vector] * 10) == "insufficient_training_data"
    score = detector.score(vector)
    assert score.contribution == 0
    assert score.raw_score is None


def test_model_training_and_scoring_are_deterministic(normal_event, profile) -> None:
    base = build_feature_vector(normal_event, profile)
    training = [replace(base, failed_login_count=float(index % 3), login_hour_deviation=float(index % 5) / 10) for index in range(60)]
    anomaly = replace(base, failed_login_count=20.0, unknown_device=1.0, location_anomaly=1.0)
    first = IsolationForestDetector(random_state=42)
    second = IsolationForestDetector(random_state=42)

    assert first.fit(training) == "ready"
    assert second.fit(training) == "ready"
    first_score = first.score(anomaly)
    second_score = second.score(anomaly)

    assert first_score == second_score
    assert 0 <= first_score.contribution <= config.AI_MAX_CONTRIBUTION
    assert first_score.anomaly_percentile is not None
    assert "not an attack probability" in first_score.message


def test_feature_vector_order_matches_versioned_schema(normal_event, profile) -> None:
    vector = build_feature_vector(normal_event, profile)

    assert len(feature_row(vector)) == len(config.FEATURE_ORDER)
    assert feature_row(vector) == [vector.as_mapping()[name] for name in config.FEATURE_ORDER]


def test_ai_contribution_is_additive_not_a_hidden_override(normal_event, profile) -> None:
    features = build_feature_vector(normal_event, profile)
    hit = RuleHit("UNKNOWN_DEVICE", 12.0, "Unknown device", "new", "known")
    model = ModelScore("ready", 0.5, 80.0, 15.0, "test", "test")
    result = combine_risk(normal_event, features, (hit,), model)

    assert result.rule_contribution == 12
    assert result.ai_contribution == 15
    assert result.contextual_contribution == 0
    assert result.final_risk_score == 27
