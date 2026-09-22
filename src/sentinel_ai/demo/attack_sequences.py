"""Deterministic multi-event Attack Lab scenarios."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta

from sentinel_ai.demo.generator import build_scenario_event
from sentinel_ai.domain import ActivityEvent, Employee


ATTACK_LAB_SCENARIOS = {
    "account_compromise": "Account compromise",
    "credential_attack": "Credential attack",
    "privilege_abuse": "Privilege abuse",
    "data_exfiltration": "Data exfiltration",
}


def _event(employee: Employee, scenario: str, timestamp: datetime, event_id: str, run_scenario: str) -> ActivityEvent:
    return replace(build_scenario_event(employee, scenario, timestamp, event_id), timestamp=timestamp, scenario=run_scenario)


def build_attack_sequence(
    employee: Employee,
    scenario: str,
    start_time: datetime,
    simulation_id: str,
    intensity: str = "standard",
) -> list[ActivityEvent]:
    if scenario not in ATTACK_LAB_SCENARIOS:
        raise ValueError(f"Unknown Attack Lab scenario: {scenario}")
    if intensity not in {"standard", "elevated"}:
        raise ValueError(f"Unknown Attack Lab intensity: {intensity}")
    event_id = lambda index: f"{simulation_id}-E{index:02d}"
    at = lambda minutes: start_time + timedelta(minutes=minutes)

    if scenario == "account_compromise":
        auth = _event(employee, "outside_hours_login", at(0), event_id(1), scenario)
        auth = replace(auth, failed_login_count=6 if intensity == "standard" else 12)
        device = _event(employee, "unknown_device_login", at(4), event_id(2), scenario)
        access = _event(employee, "sensitive_file_access", at(9), event_id(3), scenario)
        return [auth, device, access]
    if scenario == "credential_attack":
        attempts = _event(employee, "brute_force_attempt", at(0), event_id(1), scenario)
        attempts = replace(attempts, login_success=False, failed_login_count=9 if intensity == "standard" else 18)
        success = _event(employee, "unknown_device_login", at(3), event_id(2), scenario)
        return [attempts, success]
    if scenario == "privilege_abuse":
        login = _event(employee, "normal_login", at(0), event_id(1), scenario)
        elevated = _event(employee, "privilege_escalation", at(5), event_id(2), scenario)
        access = _event(employee, "sensitive_file_access", at(8), event_id(3), scenario)
        return [login, elevated, access]
    access = _event(employee, "sensitive_file_access", at(0), event_id(1), scenario)
    download = _event(employee, "bulk_download", at(5), event_id(2), scenario)
    if intensity == "elevated":
        download = replace(download, download_count=150, download_size_mb=90.0)
    return [access, download]
