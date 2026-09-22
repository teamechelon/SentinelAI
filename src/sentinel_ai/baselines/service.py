"""Build prior-only employee behavior profiles from normal history."""

from __future__ import annotations

from collections import Counter, defaultdict
from statistics import mean

import numpy as np

from sentinel_ai.domain import ActivityEvent, BehaviourProfile, Employee


def _mode(values: list[str], default: str) -> str:
    if not values:
        return default
    return Counter(values).most_common(1)[0][0]


def _frequent_values(values: list[str], minimum_share: float = 0.1) -> tuple[str, ...]:
    if not values:
        return ()
    counts = Counter(values)
    threshold = max(1, int(len(values) * minimum_share))
    return tuple(sorted(value for value, count in counts.items() if count >= threshold))


def build_profile(employee: Employee, historical_events: list[ActivityEvent]) -> BehaviourProfile:
    """Create one profile using only events supplied as historical context."""

    normal_events = [event for event in historical_events if not event.is_suspicious and event.scenario == "normal"]
    login_events = [event for event in normal_events if event.activity_type == "login" and event.login_success]
    login_hours = [event.timestamp.hour + event.timestamp.minute / 60 for event in login_events]
    download_events = [event for event in normal_events if event.download_count > 0]
    file_events = [event for event in normal_events if event.file_name]

    normal_start = float(np.quantile(login_hours, 0.05)) if login_hours else 8.0
    normal_end = float(np.quantile(login_hours, 0.95)) if login_hours else 19.0
    countries = _frequent_values([event.country for event in login_events]) or (employee.home_country,)
    cities = _frequent_values([event.city for event in login_events]) or (employee.home_city,)
    devices = tuple(sorted({event.device_id for event in normal_events if event.is_known_device})) or employee.known_devices
    sensitivities = _frequent_values([event.file_sensitivity for event in file_events]) or ("Public", "Internal")

    return BehaviourProfile(
        employee_id=employee.employee_id,
        normal_login_start=round(normal_start, 2),
        normal_login_end=round(normal_end, 2),
        usual_countries=countries,
        usual_cities=cities,
        known_devices=devices,
        average_download_count=round(mean([event.download_count for event in download_events]), 2) if download_events else 0.0,
        average_download_size_mb=round(mean([event.download_size_mb for event in download_events]), 2) if download_events else 0.0,
        typical_file_sensitivity=sensitivities,
        normal_privilege=_mode([event.current_privilege for event in normal_events], employee.normal_privilege),
        average_failed_login_count=round(mean([event.failed_login_count for event in login_events]), 2) if login_events else 0.0,
        history_event_count=len(normal_events),
        confidence=round(min(1.0, len(normal_events) / 30.0), 3),
    )


def build_profiles(employees: list[Employee], historical_events: list[ActivityEvent]) -> dict[str, BehaviourProfile]:
    grouped: dict[str, list[ActivityEvent]] = defaultdict(list)
    for event in historical_events:
        grouped[event.employee_id].append(event)
    return {employee.employee_id: build_profile(employee, grouped[employee.employee_id]) for employee in employees}

