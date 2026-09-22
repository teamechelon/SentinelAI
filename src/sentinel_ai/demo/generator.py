"""Deterministic synthetic employees and activity events for the local demo."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from sentinel_ai import config
from sentinel_ai.domain import ActivityEvent, Employee


LOCATION_CATALOG = {
    "Bangalore, India": ("India", "Bangalore", 12.9716, 77.5946),
    "Mumbai, India": ("India", "Mumbai", 19.0760, 72.8777),
    "Hyderabad, India": ("India", "Hyderabad", 17.3850, 78.4867),
    "Delhi, India": ("India", "Delhi", 28.6139, 77.2090),
    "Singapore": ("Singapore", "Singapore", 1.3521, 103.8198),
    "Dubai, UAE": ("United Arab Emirates", "Dubai", 25.2048, 55.2708),
    "London, UK": ("United Kingdom", "London", 51.5074, -0.1278),
    "New York, USA": ("United States", "New York", 40.7128, -74.0060),
}

DEPARTMENTS = ("Engineering", "Finance", "Human Resources", "Sales", "Operations")
EMPLOYEE_NAMES = (
    "Asha Rao", "Arjun Mehta", "Kavya Iyer", "Rohan Shah", "Meera Nair",
    "Vikram Singh", "Diya Patel", "Kabir Verma", "Nisha Gupta", "Rahul Das",
    "Ananya Joshi", "Sanjay Kumar", "Ishita Bose", "Dev Malhotra", "Pooja Menon",
    "Neel Kapoor", "Tara Reddy", "Amit Bhat", "Riya Chawla", "Kiran Kulkarni",
    "Sara Khan", "Mohan Pillai", "Leena Jain", "Aditya Roy", "Maya Sethi",
    "Naveen George", "Priya Soni", "Varun Arora", "Sneha Paul", "Harish Rao",
)
HOME_LOCATIONS = ("Bangalore, India", "Mumbai, India", "Hyderabad, India", "Delhi, India")
FILE_NAMES = ("project-plan.pdf", "quarterly-report.xlsx", "team-roster.csv", "design-notes.md", "policy-guide.pdf")
NORMAL_SENSITIVITIES = ("Public", "Internal", "Internal", "Internal")
SUSPICIOUS_SCENARIOS = (
    "outside_hours_login",
    "unknown_device_login",
    "unusual_location_login",
    "impossible_travel",
    "multiple_failed_logins",
    "bulk_download",
    "sensitive_file_access",
    "privilege_escalation",
    "combined_account_compromise",
)


def generate_employees(count: int = 30) -> list[Employee]:
    if count < 25:
        raise ValueError("SentinelAI requires at least 25 synthetic employees")
    employees: list[Employee] = []
    for index in range(count):
        employee_id = f"EMP-{index + 1:03d}"
        location_name = HOME_LOCATIONS[index % len(HOME_LOCATIONS)]
        country, city, latitude, longitude = LOCATION_CATALOG[location_name]
        employees.append(
            Employee(
                employee_id=employee_id,
                employee_name=EMPLOYEE_NAMES[index % len(EMPLOYEE_NAMES)],
                department=DEPARTMENTS[index % len(DEPARTMENTS)],
                home_country=country,
                home_city=city,
                home_latitude=latitude,
                home_longitude=longitude,
                known_devices=(f"{employee_id}-LAPTOP", f"{employee_id}-MOBILE"),
                normal_privilege="Manager" if index % 11 == 0 else "Employee",
            )
        )
    return employees


def _normal_event(employee: Employee, event_id: str, timestamp: datetime, rng: random.Random) -> ActivityEvent:
    activity_type = rng.choices(("login", "file_access", "download"), weights=(5, 3, 2), k=1)[0]
    is_download = activity_type == "download"
    has_file = activity_type in {"file_access", "download"}
    download_count = rng.randint(1, 16) if is_download else 0
    download_size = round(rng.uniform(2, 45), 2) if is_download else 0.0
    return ActivityEvent(
        event_id=event_id,
        employee_id=employee.employee_id,
        employee_name=employee.employee_name,
        department=employee.department,
        timestamp=timestamp,
        activity_type=activity_type,
        login_success=True,
        failed_login_count=1 if activity_type == "login" and rng.random() < 0.08 else 0,
        ip_address=f"203.0.113.{rng.randint(1, 250)}",
        country=employee.home_country,
        city=employee.home_city,
        latitude=employee.home_latitude,
        longitude=employee.home_longitude,
        device_id=rng.choice(employee.known_devices),
        is_known_device=True,
        file_name=rng.choice(FILE_NAMES) if has_file else "",
        file_sensitivity=rng.choice(NORMAL_SENSITIVITIES) if has_file else "Public",
        download_count=download_count,
        download_size_mb=download_size,
        previous_privilege=employee.normal_privilege,
        current_privilege=employee.normal_privilege,
        scenario="normal",
        is_suspicious=False,
    )


def build_scenario_event(
    employee: Employee,
    scenario: str,
    timestamp: datetime,
    event_id: str,
) -> ActivityEvent:
    """Create one deterministic scenario event from an employee profile."""

    event = ActivityEvent(
        event_id=event_id,
        employee_id=employee.employee_id,
        employee_name=employee.employee_name,
        department=employee.department,
        timestamp=timestamp,
        activity_type="login",
        login_success=True,
        failed_login_count=0,
        ip_address="198.51.100.25",
        country=employee.home_country,
        city=employee.home_city,
        latitude=employee.home_latitude,
        longitude=employee.home_longitude,
        device_id=employee.known_devices[0],
        is_known_device=True,
        file_name="",
        file_sensitivity="Public",
        download_count=0,
        download_size_mb=0.0,
        previous_privilege=employee.normal_privilege,
        current_privilege=employee.normal_privilege,
        scenario=scenario,
        is_suspicious=scenario not in {"normal_login", "legitimate_travel"},
        is_approved_travel=scenario == "legitimate_travel",
    )
    values = event.__dict__.copy()

    if scenario == "normal_login":
        values.update(timestamp=timestamp.replace(hour=10, minute=0), scenario="normal_login", is_suspicious=False)
    elif scenario == "outside_hours_login":
        values.update(timestamp=timestamp.replace(hour=2, minute=15))
    elif scenario == "unknown_device_login":
        values.update(device_id=f"UNRECOGNIZED-{employee.employee_id}", is_known_device=False)
    elif scenario == "unusual_location_login":
        country, city, latitude, longitude = LOCATION_CATALOG["Singapore"]
        values.update(country=country, city=city, latitude=latitude, longitude=longitude, ip_address="198.51.100.61")
    elif scenario == "impossible_travel":
        country, city, latitude, longitude = LOCATION_CATALOG["London, UK"]
        values.update(country=country, city=city, latitude=latitude, longitude=longitude, ip_address="198.51.100.81")
    elif scenario in {"multiple_failed_logins", "brute_force_attempt"}:
        values.update(failed_login_count=9, device_id=f"UNRECOGNIZED-{employee.employee_id}", is_known_device=False)
    elif scenario == "bulk_download":
        values.update(activity_type="download", file_name="engineering-archive.zip", file_sensitivity="Internal", download_count=75, download_size_mb=35.0)
    elif scenario == "sensitive_file_access":
        values.update(activity_type="file_access", file_name="payroll-master.xlsx", file_sensitivity="Restricted")
    elif scenario == "privilege_escalation":
        values.update(activity_type="privilege_change", current_privilege="Administrator")
    elif scenario == "combined_account_compromise":
        country, city, latitude, longitude = LOCATION_CATALOG["London, UK"]
        values.update(
            timestamp=timestamp.replace(hour=1, minute=45),
            country=country,
            city=city,
            latitude=latitude,
            longitude=longitude,
            ip_address="198.51.100.99",
            device_id=f"UNRECOGNIZED-{employee.employee_id}",
            is_known_device=False,
            failed_login_count=12,
            activity_type="login",
            file_name="restricted-customer-export.zip",
            file_sensitivity="Restricted",
            download_count=120,
            download_size_mb=60.0,
            current_privilege="Administrator",
        )
    elif scenario == "legitimate_travel":
        country, city, latitude, longitude = LOCATION_CATALOG["London, UK"]
        values.update(country=country, city=city, latitude=latitude, longitude=longitude, ip_address="198.51.100.75")
    else:
        raise ValueError(f"Unknown simulation scenario: {scenario}")
    return ActivityEvent(**values)


def generate_dataset(seed: int = config.RANDOM_SEED) -> tuple[list[Employee], list[ActivityEvent]]:
    """Return at least 1,000 normal and 100 suspicious reproducible events."""

    rng = random.Random(seed)
    employees = generate_employees(30)
    events: list[ActivityEvent] = []
    event_number = 1
    start = datetime(2025, 1, 6, tzinfo=timezone.utc)

    for employee_index, employee in enumerate(employees):
        for day in range(40):
            hour = rng.randint(8, 18)
            minute = rng.choice((0, 10, 20, 30, 40, 50))
            timestamp = start + timedelta(days=day, minutes=employee_index * 2)
            timestamp = timestamp.replace(hour=hour, minute=minute)
            events.append(_normal_event(employee, f"EVT-{event_number:06d}", timestamp, rng))
            event_number += 1

    suspicious_start = start + timedelta(days=55)
    for repetition in range(12):
        for scenario_index, scenario in enumerate(SUSPICIOUS_SCENARIOS):
            employee = employees[(repetition * len(SUSPICIOUS_SCENARIOS) + scenario_index) % len(employees)]
            timestamp = suspicious_start + timedelta(days=repetition, hours=scenario_index * 2)
            scenario_event = build_scenario_event(employee, scenario, timestamp, f"EVT-{event_number + (1 if scenario in {'impossible_travel', 'combined_account_compromise'} else 0):06d}")
            if scenario in {"impossible_travel", "combined_account_compromise"}:
                anchor_time = scenario_event.timestamp - timedelta(hours=1)
                anchor = build_scenario_event(employee, "normal_login", anchor_time, f"EVT-{event_number:06d}")
                anchor = ActivityEvent(**{**anchor.__dict__, "timestamp": anchor_time})
                events.append(anchor)
                event_number += 1
            events.append(scenario_event)
            event_number += 1

    for index in range(12):
        employee = employees[index]
        arrival_time = suspicious_start + timedelta(days=20 + index, hours=12)
        travel_event = build_scenario_event(employee, "legitimate_travel", arrival_time, f"EVT-{event_number + 1:06d}")
        anchor_time = travel_event.timestamp - timedelta(hours=12)
        anchor = build_scenario_event(employee, "normal_login", anchor_time, f"EVT-{event_number:06d}")
        anchor = ActivityEvent(**{**anchor.__dict__, "timestamp": anchor_time})
        events.append(anchor)
        event_number += 1
        events.append(travel_event)
        event_number += 1

    events.sort(key=lambda item: (item.timestamp, item.event_id))
    return employees, events
