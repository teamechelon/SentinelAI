"""Prior-only feature engineering for employee activity events."""

from __future__ import annotations

import math

from sentinel_ai import config
from sentinel_ai.domain import ActivityEvent, BehaviourProfile, FeatureVector


PRIVILEGE_RANK = {"Employee": 0, "Manager": 1, "Administrator": 2}


def haversine_distance_km(
    latitude_1: float | None,
    longitude_1: float | None,
    latitude_2: float | None,
    longitude_2: float | None,
) -> float:
    if None in (latitude_1, longitude_1, latitude_2, longitude_2):
        return 0.0
    lat_1, lon_1, lat_2, lon_2 = map(math.radians, (latitude_1, longitude_1, latitude_2, longitude_2))
    delta_lat = lat_2 - lat_1
    delta_lon = lon_2 - lon_1
    a = math.sin(delta_lat / 2) ** 2 + math.cos(lat_1) * math.cos(lat_2) * math.sin(delta_lon / 2) ** 2
    return 6371.008 * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _safe_ratio(value: float, baseline: float) -> float:
    denominator = max(abs(baseline), 1.0)
    return (value - baseline) / denominator


def build_feature_vector(
    event: ActivityEvent,
    profile: BehaviourProfile,
    previous_successful_login: ActivityEvent | None = None,
) -> FeatureVector:
    login_hour = event.timestamp.hour + event.timestamp.minute / 60
    if login_hour < profile.normal_login_start:
        hour_deviation = profile.normal_login_start - login_hour
    elif login_hour > profile.normal_login_end:
        hour_deviation = login_hour - profile.normal_login_end
    else:
        hour_deviation = 0.0

    outside_hours = float(hour_deviation > 0 and event.activity_type == "login")
    unknown_device = float(not event.is_known_device or event.device_id not in profile.known_devices)
    location_anomaly = float(event.country not in profile.usual_countries or event.city not in profile.usual_cities)
    sensitive_file = float(event.file_sensitivity not in profile.typical_file_sensitivity or event.file_sensitivity in {"Confidential", "Restricted"})
    privilege_escalation = float(PRIVILEGE_RANK.get(event.current_privilege, 0) > PRIVILEGE_RANK.get(event.previous_privilege, 0))

    travel_speed = 0.0
    impossible_travel = 0.0
    if previous_successful_login and event.activity_type == "login" and event.login_success:
        elapsed_hours = (event.timestamp - previous_successful_login.timestamp).total_seconds() / 3600
        if elapsed_hours > 0:
            distance = haversine_distance_km(
                previous_successful_login.latitude,
                previous_successful_login.longitude,
                event.latitude,
                event.longitude,
            )
            travel_speed = distance / elapsed_hours
            impossible_travel = float(
                distance >= config.IMPOSSIBLE_TRAVEL_MIN_DISTANCE_KM
                and travel_speed > config.IMPOSSIBLE_TRAVEL_MAX_SPEED_KMH
            )

    return FeatureVector(
        login_hour_deviation=round(hour_deviation, 4),
        outside_working_hours=outside_hours,
        unknown_device=unknown_device,
        location_anomaly=location_anomaly,
        failed_login_count=float(max(0, event.failed_login_count)),
        download_count_deviation=round(_safe_ratio(float(event.download_count), profile.average_download_count), 4),
        download_size_deviation=round(_safe_ratio(float(event.download_size_mb), profile.average_download_size_mb), 4),
        sensitive_file=sensitive_file,
        privilege_escalation=privilege_escalation,
        travel_speed_kmh=round(min(max(travel_speed, 0.0), 20_000.0), 4),
        impossible_travel=impossible_travel,
    )


def feature_row(vector: FeatureVector) -> list[float]:
    mapping = vector.as_mapping()
    return [mapping[name] for name in config.FEATURE_ORDER]

