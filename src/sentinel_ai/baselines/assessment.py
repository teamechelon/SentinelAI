"""Prior-only personal and peer behavioral assessment."""

from __future__ import annotations

from sentinel_ai import config
from sentinel_ai.baselines.service import build_peer_profile, build_profile, peer_group_key
from sentinel_ai.domain import (
    ActivityEvent,
    BehaviouralAssessment,
    BehaviouralSignal,
    BehaviourProfile,
    Employee,
    PeerBehaviourProfile,
)


def _signal(name: str, unusual: bool, observed: object, expected: object) -> BehaviouralSignal:
    return BehaviouralSignal(
        signal_name=name,
        is_unusual=unusual,
        observed_value=str(observed),
        expected_value=str(expected),
    )


def _signals(
    event: ActivityEvent,
    profile: BehaviourProfile | PeerBehaviourProfile,
    history: list[ActivityEvent],
    *,
    peer: bool,
) -> tuple[BehaviouralSignal, ...]:
    signals: list[BehaviouralSignal] = []
    login_history = [item for item in history if item.activity_type == "login" and item.login_success]
    download_history = [item for item in history if item.download_count > 0]
    file_history = [item for item in history if item.file_name]

    if event.activity_type == "login" and login_history:
        login_hour = event.timestamp.hour + event.timestamp.minute / 60
        start = profile.normal_login_start
        end = profile.normal_login_end
        if start is not None and end is not None:
            signals.append(
                _signal(
                    "login_hour",
                    login_hour < start or login_hour > end,
                    event.timestamp.strftime("%H:%M"),
                    f"{start:.2f}-{end:.2f}",
                )
            )
        signals.append(
            _signal(
                "location",
                event.country not in profile.usual_countries or event.city not in profile.usual_cities,
                f"{event.city}, {event.country}",
                f"cities={', '.join(profile.usual_cities)}; countries={', '.join(profile.usual_countries)}",
            )
        )
        failed_average = profile.average_failed_login_count
        if failed_average is not None:
            failed_threshold = max(float(config.FAILED_LOGIN_THRESHOLD), failed_average * 3.0)
            signals.append(
                _signal(
                    "failed_login_count",
                    event.failed_login_count >= failed_threshold,
                    event.failed_login_count,
                    f"< {failed_threshold:.2f}",
                )
            )

    if history:
        if peer:
            device_unusual = not event.is_known_device
            device_expected = "a device registered to the employee"
        else:
            device_unusual = not event.is_known_device or event.device_id not in profile.known_devices
            device_expected = ", ".join(profile.known_devices)
        signals.append(_signal("device", device_unusual, event.device_id, device_expected))

        signals.append(
            _signal(
                "privilege",
                event.current_privilege != profile.normal_privilege,
                event.current_privilege,
                profile.normal_privilege,
            )
        )

    if (event.activity_type == "download" or event.download_count > 0) and download_history:
        count_average = profile.average_download_count
        size_average = profile.average_download_size_mb
        if count_average is not None:
            count_threshold = max(1.0, count_average * 3.0)
            signals.append(
                _signal("download_count", event.download_count > count_threshold, event.download_count, f"<= {count_threshold:.2f}")
            )
        if size_average is not None:
            size_threshold = max(1.0, size_average * 3.0)
            signals.append(
                _signal(
                    "download_size_mb",
                    event.download_size_mb > size_threshold,
                    f"{event.download_size_mb:.2f}",
                    f"<= {size_threshold:.2f}",
                )
            )

    if (event.file_name or event.activity_type in {"file_access", "download"}) and file_history:
        signals.append(
            _signal(
                "file_sensitivity",
                event.file_sensitivity not in profile.typical_file_sensitivity,
                event.file_sensitivity,
                ", ".join(profile.typical_file_sensitivity),
            )
        )

    return tuple(signals)


def _deviation(signals: tuple[BehaviouralSignal, ...]) -> float | None:
    if not signals:
        return None
    return round(sum(signal.is_unusual for signal in signals) / len(signals), 4)


def _comparison_case(personal: float | None, peer: float | None) -> str:
    if personal is None and peer is None:
        return "insufficient_personal_and_peer_history"
    if personal is None:
        return "insufficient_personal_history"
    if peer is None:
        return "insufficient_peer_history"
    personal_unusual = personal > 0
    peer_unusual = peer > 0
    if personal_unusual and peer_unusual:
        return "abnormal_personal_abnormal_peer"
    if personal_unusual:
        return "abnormal_personal_normal_peer"
    if peer_unusual:
        return "normal_personal_abnormal_peer"
    return "normal_personal_normal_peer"


def build_behavioural_assessment(
    event: ActivityEvent,
    employee: Employee,
    employees: list[Employee],
    historical_events: list[ActivityEvent],
) -> BehaviouralAssessment:
    """Compare an event with prior normal personal history and other peers.

    History is strictly earlier than the evaluated event and excludes its event
    ID. The target employee is excluded from the peer profile so their personal
    behavior cannot define what is normal for their peers.
    """

    eligible_history = [
        item
        for item in historical_events
        if item.event_id != event.event_id
        and item.timestamp < event.timestamp
        and not item.is_suspicious
        and item.scenario == "normal"
    ]
    personal_history = [item for item in eligible_history if item.employee_id == employee.employee_id]
    personal_profile = build_profile(employee, personal_history)

    key = peer_group_key(employee)
    peers = [
        candidate
        for candidate in employees
        if candidate.employee_id != employee.employee_id and peer_group_key(candidate) == key
    ]
    peer_ids = {peer.employee_id for peer in peers}
    peer_history = [item for item in eligible_history if item.employee_id in peer_ids]
    peer_profile = build_peer_profile(key, peers, peer_history)

    personal_signals = _signals(event, personal_profile, personal_history, peer=False)
    peer_signals = _signals(event, peer_profile, peer_history, peer=True)
    personal_deviation = _deviation(personal_signals)
    peer_deviation = _deviation(peer_signals)
    personal_status = "no_history" if not personal_history else "sufficient" if personal_profile.confidence >= 1.0 else "limited"

    return BehaviouralAssessment(
        event_id=event.event_id,
        employee_id=event.employee_id,
        peer_group=key,
        personal_deviation=personal_deviation,
        peer_deviation=peer_deviation,
        personal_confidence=personal_profile.confidence,
        peer_confidence=peer_profile.confidence,
        personal_status=personal_status,
        peer_status=peer_profile.status,
        comparison_case=_comparison_case(personal_deviation, peer_deviation),
        personal_signals=personal_signals,
        peer_signals=peer_signals,
    )
