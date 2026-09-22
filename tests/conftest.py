"""Shared deterministic fixtures for SentinelAI tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from sentinel_ai.domain import ActivityEvent, BehaviourProfile, Employee


@pytest.fixture
def employee() -> Employee:
    return Employee(
        employee_id="EMP-TEST",
        employee_name="Test Analyst",
        department="Engineering",
        home_country="India",
        home_city="Bangalore",
        home_latitude=12.9716,
        home_longitude=77.5946,
        known_devices=("TEST-LAPTOP", "TEST-MOBILE"),
        normal_privilege="Employee",
    )


@pytest.fixture
def profile(employee: Employee) -> BehaviourProfile:
    return BehaviourProfile(
        employee_id=employee.employee_id,
        normal_login_start=8.0,
        normal_login_end=19.0,
        usual_countries=("India",),
        usual_cities=("Bangalore",),
        known_devices=employee.known_devices,
        average_download_count=10.0,
        average_download_size_mb=20.0,
        typical_file_sensitivity=("Public", "Internal"),
        normal_privilege="Employee",
        average_failed_login_count=0.1,
        history_event_count=30,
        confidence=1.0,
    )


@pytest.fixture
def normal_event(employee: Employee) -> ActivityEvent:
    return ActivityEvent(
        event_id="EVT-TEST",
        employee_id=employee.employee_id,
        employee_name=employee.employee_name,
        department=employee.department,
        timestamp=datetime(2025, 3, 1, 10, 0, tzinfo=timezone.utc),
        activity_type="login",
        login_success=True,
        failed_login_count=0,
        ip_address="203.0.113.10",
        country="India",
        city="Bangalore",
        latitude=12.9716,
        longitude=77.5946,
        device_id="TEST-LAPTOP",
        is_known_device=True,
        file_name="",
        file_sensitivity="Public",
        download_count=0,
        download_size_mb=0.0,
        previous_privilege="Employee",
        current_privilege="Employee",
        scenario="normal",
        is_suspicious=False,
        is_approved_travel=False,
    )


@pytest.fixture
def event_factory(normal_event: ActivityEvent):
    def factory(**changes: object) -> ActivityEvent:
        return replace(normal_event, **changes)

    return factory
