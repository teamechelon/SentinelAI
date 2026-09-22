"""Ordered sequence rules that never modify event-level risk scores."""

from __future__ import annotations

from collections.abc import Callable

from sentinel_ai.domain import ActivityEvent, SequenceFinding


def _ordered_match(
    events: list[ActivityEvent],
    predicates: tuple[Callable[[ActivityEvent], bool], ...],
    max_window_minutes: int,
) -> tuple[ActivityEvent, ...] | None:
    ordered = sorted(events, key=lambda item: (item.timestamp, item.event_id))
    for start_index, first in enumerate(ordered):
        if not predicates[0](first):
            continue
        matched = [first]
        cursor = start_index + 1
        for predicate in predicates[1:]:
            while cursor < len(ordered) and not predicate(ordered[cursor]):
                cursor += 1
            if cursor >= len(ordered):
                break
            matched.append(ordered[cursor])
            cursor += 1
        if len(matched) == len(predicates):
            minutes = (matched[-1].timestamp - matched[0].timestamp).total_seconds() / 60
            if 0 <= minutes <= max_window_minutes:
                return tuple(matched)
    return None


def analyze_sequences(events: list[ActivityEvent]) -> tuple[SequenceFinding, ...]:
    if not events:
        return ()
    employee_ids = {event.employee_id for event in events}
    if len(employee_ids) != 1:
        raise ValueError("Sequence analysis requires events from one employee")
    rules = (
        (
            "BRUTE_FORCE_SUCCESS", "Failed authentication followed by successful login", "High", 15,
            (lambda e: e.activity_type == "login" and (not e.login_success or e.failed_login_count >= 5), lambda e: e.activity_type == "login" and e.login_success),
            ("Repeated or failed authentication observed", "A later successful login was observed"),
        ),
        (
            "ACCOUNT_COMPROMISE", "Authentication anomaly followed by suspicious access", "Critical", 30,
            (lambda e: e.activity_type == "login" and e.failed_login_count >= 5, lambda e: e.activity_type == "login" and not e.is_known_device, lambda e: e.activity_type == "file_access" and e.file_sensitivity in {"Confidential", "Restricted"}),
            ("Authentication anomaly observed", "Unknown device login observed", "Sensitive resource access observed"),
        ),
        (
            "PRIVILEGE_ABUSE", "Login followed by privilege escalation and sensitive access", "Critical", 30,
            (lambda e: e.activity_type == "login" and e.login_success, lambda e: e.current_privilege != e.previous_privilege, lambda e: e.activity_type == "file_access" and e.file_sensitivity in {"Confidential", "Restricted"}),
            ("Successful login observed", "Privilege increase observed", "Sensitive resource access observed"),
        ),
        (
            "POSSIBLE_EXFILTRATION", "Sensitive access followed by bulk transfer", "High", 30,
            (lambda e: e.activity_type == "file_access" and e.file_sensitivity in {"Confidential", "Restricted"}, lambda e: e.activity_type == "download" and (e.download_count >= 50 or e.download_size_mb >= 50)),
            ("Sensitive resource access observed", "Bulk or large download observed"),
        ),
    )
    findings: list[SequenceFinding] = []
    for code, title, severity, window, predicates, evidence in rules:
        matched = _ordered_match(events, predicates, window)
        if matched:
            findings.append(SequenceFinding(code, title, severity, "observed", tuple(event.event_id for event in matched), window, evidence))
    return tuple(findings)
