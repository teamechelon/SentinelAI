"""Deterministic ordered-event rule contracts."""

from datetime import datetime, timezone

import pytest

from sentinel_ai.demo import ATTACK_LAB_SCENARIOS, build_attack_sequence
from sentinel_ai.detection import analyze_sequences


@pytest.mark.parametrize(
    ("scenario", "expected_code", "event_count"),
    [
        ("account_compromise", "ACCOUNT_COMPROMISE", 3),
        ("credential_attack", "BRUTE_FORCE_SUCCESS", 2),
        ("privilege_abuse", "PRIVILEGE_ABUSE", 3),
        ("data_exfiltration", "POSSIBLE_EXFILTRATION", 2),
    ],
)
def test_attack_sequences_have_ordered_evidence(employee, scenario, expected_code, event_count) -> None:
    events = build_attack_sequence(employee, scenario, datetime(2025, 7, 1, tzinfo=timezone.utc), "RUN-TEST")
    findings = analyze_sequences(events)

    assert len(events) == event_count
    assert [event.timestamp for event in events] == sorted(event.timestamp for event in events)
    finding = next(item for item in findings if item.code == expected_code)
    assert finding.event_ids == tuple(event.event_id for event in events)
    assert finding.status == "observed"


def test_attack_catalog_and_generation_reject_unknown_scenarios(employee) -> None:
    assert set(ATTACK_LAB_SCENARIOS) == {"account_compromise", "credential_attack", "privilege_abuse", "data_exfiltration"}
    with pytest.raises(ValueError, match="Unknown Attack Lab scenario"):
        build_attack_sequence(employee, "invented", datetime(2025, 7, 1, tzinfo=timezone.utc), "RUN-TEST")


def test_sequence_rules_do_not_match_reversed_order(employee) -> None:
    events = build_attack_sequence(employee, "data_exfiltration", datetime(2025, 7, 1, tzinfo=timezone.utc), "RUN-TEST")
    reversed_timestamps = [events[0].__class__(**{**events[0].__dict__, "timestamp": events[1].timestamp}), events[1].__class__(**{**events[1].__dict__, "timestamp": events[0].timestamp})]

    assert not any(item.code == "POSSIBLE_EXFILTRATION" for item in analyze_sequences(reversed_timestamps))
