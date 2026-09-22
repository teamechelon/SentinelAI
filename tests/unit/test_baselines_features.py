"""Prior-only baseline and feature engineering tests."""

from dataclasses import replace
from datetime import timedelta

from sentinel_ai.baselines import build_profile
from sentinel_ai.demo import generate_dataset
from sentinel_ai.features import build_feature_vector, haversine_distance_km


def test_profile_uses_only_normal_history() -> None:
    employees, events = generate_dataset()
    employee = employees[0]
    history = [event for event in events if event.employee_id == employee.employee_id]
    profile = build_profile(employee, history)

    assert profile.history_event_count == 40
    assert profile.usual_countries == (employee.home_country,)
    assert all("UNRECOGNIZED" not in device for device in profile.known_devices)


def test_cold_start_profile_has_safe_defaults(employee) -> None:
    profile = build_profile(employee, [])

    assert profile.normal_login_start == 8.0
    assert profile.normal_login_end == 19.0
    assert profile.history_event_count == 0
    assert profile.confidence == 0.0
    assert profile.usual_cities == ("Bangalore",)


def test_normal_event_has_no_binary_anomaly_features(normal_event, profile) -> None:
    vector = build_feature_vector(normal_event, profile)

    assert vector.outside_working_hours == 0
    assert vector.unknown_device == 0
    assert vector.location_anomaly == 0
    assert vector.impossible_travel == 0
    assert vector.privilege_escalation == 0


def test_unknown_device_and_location_are_detected(event_factory, profile) -> None:
    event = event_factory(
        device_id="NEW-DEVICE",
        is_known_device=False,
        country="Singapore",
        city="Singapore",
        latitude=1.3521,
        longitude=103.8198,
    )
    vector = build_feature_vector(event, profile)

    assert vector.unknown_device == 1
    assert vector.location_anomaly == 1


def test_impossible_travel_uses_previous_successful_login(event_factory, normal_event, profile) -> None:
    previous = replace(normal_event, timestamp=normal_event.timestamp - timedelta(hours=1))
    london = event_factory(
        country="United Kingdom",
        city="London",
        latitude=51.5074,
        longitude=-0.1278,
    )
    vector = build_feature_vector(london, profile, previous)

    assert vector.travel_speed_kmh > 900
    assert vector.impossible_travel == 1


def test_missing_coordinates_do_not_invent_impossible_travel(event_factory, normal_event, profile) -> None:
    event = event_factory(latitude=None, longitude=None)
    vector = build_feature_vector(event, profile, normal_event)

    assert vector.travel_speed_kmh == 0
    assert vector.impossible_travel == 0


def test_haversine_distance_is_geographically_reasonable() -> None:
    distance = haversine_distance_km(12.9716, 77.5946, 51.5074, -0.1278)

    assert 7_900 < distance < 8_200
