"""Personal and peer behavioral baseline contracts."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

from sentinel_ai.baselines import (
    build_behavioural_assessment,
    build_peer_profile,
    build_profile,
    peer_group_key,
)
from sentinel_ai.domain import ActivityEvent, Employee, PeerGroupKey


def make_employee(employee: Employee, employee_id: str, *, department: str = "Engineering", role: str = "Employee") -> Employee:
    return replace(
        employee,
        employee_id=employee_id,
        employee_name=f"Employee {employee_id}",
        department=department,
        known_devices=(f"{employee_id}-LAPTOP",),
        normal_privilege=role,
    )


def make_event(
    template: ActivityEvent,
    employee: Employee,
    event_id: str,
    *,
    days_before: int,
    hour: int,
    city: str = "Bangalore",
    country: str = "India",
    activity_type: str = "login",
    download_count: int = 0,
    download_size_mb: float = 0.0,
    file_name: str = "",
    file_sensitivity: str = "Public",
) -> ActivityEvent:
    return replace(
        template,
        event_id=event_id,
        employee_id=employee.employee_id,
        employee_name=employee.employee_name,
        department=employee.department,
        timestamp=(template.timestamp - timedelta(days=days_before)).replace(hour=hour, minute=0),
        activity_type=activity_type,
        country=country,
        city=city,
        device_id=employee.known_devices[0],
        is_known_device=True,
        download_count=download_count,
        download_size_mb=download_size_mb,
        file_name=file_name,
        file_sensitivity=file_sensitivity,
        previous_privilege=employee.normal_privilege,
        current_privilege=employee.normal_privilege,
        scenario="normal",
        is_suspicious=False,
    )


def case_assessment(
    employee: Employee,
    normal_event: ActivityEvent,
    *,
    personal_pattern: tuple[int, str] | None,
    peer_pattern: tuple[int, str] | None,
    event_pattern: tuple[int, str],
    peer_count: int = 2,
):
    target = make_employee(employee, "EMP-TARGET")
    peers = [make_employee(employee, f"EMP-PEER-{index}") for index in range(peer_count)]
    history: list[ActivityEvent] = []
    if personal_pattern:
        hour, city = personal_pattern
        history.extend(
            make_event(normal_event, target, f"TARGET-{index}", days_before=10 - index, hour=hour, city=city, country="Singapore" if city == "Singapore" else "India")
            for index in range(5)
        )
    if peer_pattern:
        hour, city = peer_pattern
        for peer_index, peer in enumerate(peers):
            history.extend(
                make_event(
                    normal_event,
                    peer,
                    f"PEER-{peer_index}-{index}",
                    days_before=10 - index,
                    hour=hour,
                    city=city,
                    country="Singapore" if city == "Singapore" else "India",
                )
                for index in range(5)
            )
    event_hour, event_city = event_pattern
    event = make_event(
        normal_event,
        target,
        "EVALUATED",
        days_before=0,
        hour=event_hour,
        city=event_city,
        country="Singapore" if event_city == "Singapore" else "India",
    )
    return build_behavioural_assessment(event, target, [target, *peers], [*history, event])


def test_peer_group_assignment_uses_department_and_role(employee: Employee) -> None:
    engineer = make_employee(employee, "EMP-1", department="Engineering", role="Manager")
    finance = make_employee(employee, "EMP-2", department="Finance", role="Manager")

    assert peer_group_key(engineer) == PeerGroupKey("Engineering", "Manager")
    assert peer_group_key(engineer) != peer_group_key(finance)


def test_personal_and_peer_baselines_are_constructed(employee: Employee, normal_event: ActivityEvent) -> None:
    target = make_employee(employee, "EMP-TARGET")
    peers = [make_employee(employee, "EMP-PEER-1"), make_employee(employee, "EMP-PEER-2")]
    target_history = [make_event(normal_event, target, "TARGET-LOGIN", days_before=3, hour=9)]
    peer_history = [
        make_event(normal_event, peers[0], "PEER-LOGIN", days_before=3, hour=10),
        make_event(
            normal_event,
            peers[1],
            "PEER-DOWNLOAD",
            days_before=2,
            hour=11,
            activity_type="download",
            download_count=8,
            download_size_mb=12.0,
            file_name="report.xlsx",
            file_sensitivity="Internal",
        ),
    ]

    personal = build_profile(target, target_history)
    peer = build_peer_profile(peer_group_key(target), peers, peer_history)

    assert personal.normal_login_start == personal.normal_login_end == 9.0
    assert personal.usual_cities == ("Bangalore",)
    assert peer.member_count == 2
    assert peer.contributing_member_count == 2
    assert peer.normal_login_start == peer.normal_login_end == 10.0
    assert peer.average_download_count == 8.0
    assert peer.average_download_size_mb == 12.0
    assert peer.typical_file_sensitivity == ("Internal",)


def test_current_event_is_excluded_from_both_baselines(employee: Employee, normal_event: ActivityEvent) -> None:
    target = make_employee(employee, "EMP-TARGET")
    peer = make_employee(employee, "EMP-PEER")
    personal_history = [make_event(normal_event, target, "TARGET-PRIOR", days_before=2, hour=10)]
    peer_history = [make_event(normal_event, peer, "PEER-PRIOR", days_before=2, hour=10)]
    current = make_event(normal_event, target, "CURRENT", days_before=0, hour=2, city="Singapore", country="Singapore")

    without_current = build_behavioural_assessment(current, target, [target, peer], [*personal_history, *peer_history])
    with_current = build_behavioural_assessment(current, target, [target, peer], [*personal_history, *peer_history, current])

    assert with_current == without_current
    assert with_current.personal_deviation is not None and with_current.personal_deviation > 0
    assert with_current.peer_deviation is not None and with_current.peer_deviation > 0


def test_normal_employee_and_normal_peers(employee: Employee, normal_event: ActivityEvent) -> None:
    assessment = case_assessment(
        employee,
        normal_event,
        personal_pattern=(10, "Bangalore"),
        peer_pattern=(10, "Bangalore"),
        event_pattern=(10, "Bangalore"),
    )

    assert assessment.personal_deviation == 0
    assert assessment.peer_deviation == 0
    assert assessment.comparison_case == "normal_personal_normal_peer"


def test_abnormal_employee_and_normal_peers(employee: Employee, normal_event: ActivityEvent) -> None:
    assessment = case_assessment(
        employee,
        normal_event,
        personal_pattern=(9, "Bangalore"),
        peer_pattern=(14, "Singapore"),
        event_pattern=(14, "Singapore"),
    )

    assert assessment.personal_deviation is not None and assessment.personal_deviation > 0
    assert assessment.peer_deviation == 0
    assert assessment.comparison_case == "abnormal_personal_normal_peer"


def test_normal_employee_and_abnormal_peers(employee: Employee, normal_event: ActivityEvent) -> None:
    assessment = case_assessment(
        employee,
        normal_event,
        personal_pattern=(14, "Singapore"),
        peer_pattern=(9, "Bangalore"),
        event_pattern=(14, "Singapore"),
    )

    assert assessment.personal_deviation == 0
    assert assessment.peer_deviation is not None and assessment.peer_deviation > 0
    assert assessment.comparison_case == "normal_personal_abnormal_peer"


def test_abnormal_employee_and_abnormal_peers(employee: Employee, normal_event: ActivityEvent) -> None:
    assessment = case_assessment(
        employee,
        normal_event,
        personal_pattern=(9, "Bangalore"),
        peer_pattern=(9, "Bangalore"),
        event_pattern=(2, "Singapore"),
    )

    assert assessment.personal_deviation is not None and assessment.personal_deviation > 0
    assert assessment.peer_deviation is not None and assessment.peer_deviation > 0
    assert assessment.comparison_case == "abnormal_personal_abnormal_peer"


def test_sparse_peer_group_has_independent_low_confidence(employee: Employee, normal_event: ActivityEvent) -> None:
    target = make_employee(employee, "EMP-TARGET")
    peer = make_employee(employee, "EMP-ONLY-PEER")
    history = [
        make_event(normal_event, peer, f"PEER-{index}", days_before=50 - index, hour=10)
        for index in range(40)
    ]
    current = make_event(normal_event, target, "CURRENT", days_before=0, hour=10)
    assessment = build_behavioural_assessment(current, target, [target, peer], history)

    assert assessment.peer_status == "sparse"
    assert 0 < assessment.peer_confidence < 0.5
    assert assessment.personal_confidence == 0


def test_no_usable_personal_history_falls_back_to_peer_evidence(employee: Employee, normal_event: ActivityEvent) -> None:
    assessment = case_assessment(
        employee,
        normal_event,
        personal_pattern=None,
        peer_pattern=(10, "Bangalore"),
        event_pattern=(10, "Bangalore"),
    )

    assert assessment.personal_deviation is None
    assert assessment.peer_deviation == 0
    assert assessment.personal_status == "no_history"
    assert assessment.comparison_case == "insufficient_personal_history"


def test_no_usable_peer_history_preserves_personal_evidence(employee: Employee, normal_event: ActivityEvent) -> None:
    assessment = case_assessment(
        employee,
        normal_event,
        personal_pattern=(10, "Bangalore"),
        peer_pattern=None,
        event_pattern=(10, "Bangalore"),
        peer_count=0,
    )

    assert assessment.personal_deviation == 0
    assert assessment.peer_deviation is None
    assert assessment.peer_status == "no_history"
    assert assessment.comparison_case == "insufficient_peer_history"


def test_assessment_is_deterministic(employee: Employee, normal_event: ActivityEvent) -> None:
    arguments = dict(
        personal_pattern=(9, "Bangalore"),
        peer_pattern=(14, "Singapore"),
        event_pattern=(14, "Singapore"),
    )

    first = case_assessment(employee, normal_event, **arguments)
    second = case_assessment(employee, normal_event, **arguments)

    assert first == second
    assert first.to_record() == second.to_record()
