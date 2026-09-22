"""Build prior-only employee behavior profiles from normal history."""

from __future__ import annotations

from collections import Counter, defaultdict
from statistics import mean

import numpy as np

from sentinel_ai import config
from sentinel_ai.domain import ActivityEvent, BehaviourProfile, Employee, PeerBehaviourProfile, PeerGroupKey


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
        confidence=round(min(1.0, len(normal_events) / config.PERSONAL_BASELINE_CONFIDENCE_EVENTS), 3),
    )


def build_profiles(employees: list[Employee], historical_events: list[ActivityEvent]) -> dict[str, BehaviourProfile]:
    grouped: dict[str, list[ActivityEvent]] = defaultdict(list)
    for event in historical_events:
        grouped[event.employee_id].append(event)
    return {employee.employee_id: build_profile(employee, grouped[employee.employee_id]) for employee in employees}


def peer_group_key(employee: Employee) -> PeerGroupKey:
    """Assign a deterministic peer group from stable employee metadata."""

    return PeerGroupKey(department=employee.department, role=employee.normal_privilege)


def build_peer_profile(
    key: PeerGroupKey,
    peer_employees: list[Employee],
    historical_events: list[ActivityEvent],
) -> PeerBehaviourProfile:
    """Build a peer profile from normal history belonging to the supplied peers.

    Confidence is intentionally independent from personal confidence. It combines
    normal-event volume, the number of distinct peers contributing history, and
    coverage of five evidence families. A single contributor is always sparse and
    cannot exceed one third of the member-confidence component.
    """

    peer_ids = {employee.employee_id for employee in peer_employees}
    normal_events = [
        event
        for event in historical_events
        if event.employee_id in peer_ids and not event.is_suspicious and event.scenario == "normal"
    ]
    login_events = [event for event in normal_events if event.activity_type == "login" and event.login_success]
    login_hours = [event.timestamp.hour + event.timestamp.minute / 60 for event in login_events]
    download_events = [event for event in normal_events if event.download_count > 0]
    file_events = [event for event in normal_events if event.file_name]
    device_events = [event for event in normal_events if event.is_known_device and event.device_id]
    contributing_members = {event.employee_id for event in normal_events}

    coverage = sum(
        bool(events)
        for events in (login_events, download_events, file_events, device_events, normal_events)
    ) / 5.0
    event_factor = min(1.0, len(normal_events) / config.PEER_BASELINE_CONFIDENCE_EVENTS)
    member_factor = min(1.0, len(contributing_members) / config.PEER_BASELINE_CONFIDENCE_MEMBERS)
    confidence = round(event_factor * member_factor * coverage, 3)

    if not normal_events:
        status = "no_history"
    elif len(contributing_members) < 2 or confidence < 0.5:
        status = "sparse"
    else:
        status = "sufficient"

    return PeerBehaviourProfile(
        peer_group=key,
        member_count=len(peer_employees),
        contributing_member_count=len(contributing_members),
        normal_login_start=round(float(np.quantile(login_hours, 0.05)), 2) if login_hours else None,
        normal_login_end=round(float(np.quantile(login_hours, 0.95)), 2) if login_hours else None,
        usual_countries=_frequent_values([event.country for event in login_events]),
        usual_cities=_frequent_values([event.city for event in login_events]),
        known_devices=tuple(sorted({event.device_id for event in device_events})),
        average_download_count=round(mean([event.download_count for event in download_events]), 2) if download_events else None,
        average_download_size_mb=round(mean([event.download_size_mb for event in download_events]), 2) if download_events else None,
        typical_file_sensitivity=_frequent_values([event.file_sensitivity for event in file_events]),
        normal_privilege=_mode([event.current_privilege for event in normal_events], key.role),
        average_failed_login_count=round(mean([event.failed_login_count for event in login_events]), 2) if login_events else None,
        history_event_count=len(normal_events),
        confidence=confidence,
        status=status,
    )


def build_peer_profiles(
    employees: list[Employee],
    historical_events: list[ActivityEvent],
) -> dict[PeerGroupKey, PeerBehaviourProfile]:
    grouped: dict[PeerGroupKey, list[Employee]] = defaultdict(list)
    for employee in employees:
        grouped[peer_group_key(employee)].append(employee)
    return {
        key: build_peer_profile(key, members, historical_events)
        for key, members in sorted(grouped.items())
    }

