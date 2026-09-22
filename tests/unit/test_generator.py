"""Synthetic dataset contracts."""

from collections import Counter

from sentinel_ai.baselines import peer_group_key
from sentinel_ai.demo.generator import SUSPICIOUS_SCENARIOS, generate_dataset, generate_employees


def test_dataset_meets_minimum_sizes() -> None:
    employees, events = generate_dataset()
    normal = [event for event in events if event.scenario == "normal"]
    suspicious = [event for event in events if event.is_suspicious]

    assert len(employees) >= 25
    assert len(normal) >= 1_000
    assert len(suspicious) >= 100


def test_dataset_is_reproducible() -> None:
    employees_a, events_a = generate_dataset(seed=42)
    employees_b, events_b = generate_dataset(seed=42)

    assert employees_a == employees_b
    assert events_a == events_b


def test_all_required_suspicious_scenarios_are_present() -> None:
    _, events = generate_dataset()
    observed = {event.scenario for event in events if event.is_suspicious}

    assert set(SUSPICIOUS_SCENARIOS).issubset(observed)


def test_employee_generator_enforces_demo_scale() -> None:
    try:
        generate_employees(24)
    except ValueError as error:
        assert "at least 25" in str(error)
    else:
        raise AssertionError("Expected a minimum-size validation error")


def test_events_contain_traceable_required_fields() -> None:
    _, events = generate_dataset()
    event = events[0]
    required = {
        "event_id", "employee_id", "timestamp", "activity_type", "ip_address",
        "country", "city", "device_id", "file_sensitivity", "download_count",
        "download_size_mb", "previous_privilege", "current_privilege", "scenario",
    }

    assert required.issubset(event.to_record())


def test_seed_population_contains_meaningful_peer_groups() -> None:
    employees = generate_employees()
    group_sizes = Counter(peer_group_key(employee) for employee in employees)

    assert max(group_sizes.values()) >= 5
    assert sum(size >= 2 for size in group_sizes.values()) >= 5
    engineering_employees = [
        employee
        for employee in employees
        if employee.department == "Engineering" and employee.normal_privilege == "Employee"
    ]
    assert len({employee.home_city for employee in engineering_employees}) >= 2
