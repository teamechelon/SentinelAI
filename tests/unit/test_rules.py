"""Every deterministic reason code is independently exercised."""

from dataclasses import replace
from datetime import timedelta

import pytest

from sentinel_ai.detection import evaluate_rules
from sentinel_ai.features import build_feature_vector


def codes(event, profile, previous=None) -> set[str]:
    features = build_feature_vector(event, profile, previous)
    return {hit.rule_name for hit in evaluate_rules(event, profile, features)}


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"timestamp_hour": 2}, "OUTSIDE_WORKING_HOURS"),
        ({"device_id": "NEW", "is_known_device": False}, "UNKNOWN_DEVICE"),
        ({"failed_login_count": 5}, "REPEATED_FAILED_LOGINS"),
        ({"activity_type": "download", "download_count": 40, "download_size_mb": 1.0}, "BULK_DOWNLOAD"),
        ({"activity_type": "download", "download_count": 1, "download_size_mb": 500.0}, "LARGE_DOWNLOAD"),
        ({"activity_type": "file_access", "file_name": "secret.pdf", "file_sensitivity": "Restricted"}, "SENSITIVE_FILE_ACCESS"),
        ({"activity_type": "privilege_change", "current_privilege": "Administrator"}, "PRIVILEGE_ESCALATION"),
    ],
)
def test_individual_rules(event_factory, profile, changes, expected) -> None:
    event_changes = dict(changes)
    timestamp_hour = event_changes.pop("timestamp_hour", None)
    event = event_factory(**event_changes)
    if timestamp_hour is not None:
        event = replace(event, timestamp=event.timestamp.replace(hour=timestamp_hour))

    assert expected in codes(event, profile)


def test_unusual_location_rule(event_factory, profile) -> None:
    event = event_factory(country="Singapore", city="Singapore", latitude=1.3521, longitude=103.8198)

    assert "UNUSUAL_LOCATION" in codes(event, profile)


def test_approved_travel_suppresses_location_rule(event_factory, profile) -> None:
    event = event_factory(
        country="United Kingdom",
        city="London",
        latitude=51.5074,
        longitude=-0.1278,
        is_approved_travel=True,
    )

    assert "UNUSUAL_LOCATION" not in codes(event, profile)


def test_impossible_travel_rule_contains_observed_and_expected_values(event_factory, normal_event, profile) -> None:
    prior = replace(normal_event, timestamp=normal_event.timestamp - timedelta(hours=1))
    event = event_factory(country="United Kingdom", city="London", latitude=51.5074, longitude=-0.1278)
    features = build_feature_vector(event, profile, prior)
    hit = next(hit for hit in evaluate_rules(event, profile, features) if hit.rule_name == "IMPOSSIBLE_TRAVEL")

    assert "km/h" in hit.observed_value
    assert "900" in hit.expected_value


def test_normal_event_has_no_rule_hits(normal_event, profile) -> None:
    assert codes(normal_event, profile) == set()
