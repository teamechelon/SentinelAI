"""Evidence, confidence, and false-positive safeguards for ATT&CK mapping."""

from datetime import timedelta

from sentinel_ai.detection import analyze_sequences
from sentinel_ai.graph import GraphFinding
from sentinel_ai.mitre import build_report, map_evidence


def detection(event_id: str, *rules: str, risk_level: str = "Low") -> dict:
    return {
        "event_id": event_id,
        "risk_level": risk_level,
        "final_risk_score": 99.0,
        "triggered_rules": [{"rule_name": name} for name in rules],
    }


def test_normal_and_high_model_score_do_not_create_mapping(normal_event) -> None:
    assert map_evidence([normal_event], [detection(normal_event.event_id)]) == ()


def test_direct_rules_map_only_supported_behaviours(event_factory) -> None:
    unknown = event_factory(event_id="E-UNKNOWN", is_known_device=False)
    failed = event_factory(event_id="E-FAILED", login_success=False, failed_login_count=9)
    mappings = map_evidence(
        [unknown, failed],
        [detection(unknown.event_id, "UNKNOWN_DEVICE"), detection(failed.event_id, "REPEATED_FAILED_LOGINS")],
    )
    assert {item.technique_id for item in mappings} == {"T1078", "T1110"}
    assert all(item.confidence == "low" for item in mappings)


def test_ordered_sequence_maps_and_story_timeline_is_chronological(event_factory) -> None:
    failed = event_factory(event_id="E1", login_success=False, failed_login_count=9)
    success = event_factory(
        event_id="E2",
        timestamp=failed.timestamp + timedelta(minutes=3),
        login_success=True,
        failed_login_count=0,
        is_known_device=False,
    )
    sequence = analyze_sequences([success, failed])
    report = build_report(
        "attack_run", "RUN-1", [success, failed],
        [detection("E1", "REPEATED_FAILED_LOGINS", risk_level="High"), detection("E2", "UNKNOWN_DEVICE", risk_level="Medium")],
        sequence,
    )
    assert [entry.event_id for entry in report.timeline] == ["E1", "E2"]
    assert {item.technique_id for item in report.mappings} == {"T1110", "T1078"}
    assert all(item.confidence == "medium" for item in report.mappings)
    assert report.threat_story.sequence_context


def test_graph_corroborates_but_never_originates_mapping(normal_event) -> None:
    graph = GraphFinding(
        finding_type="SHARED_DEVICE",
        severity="high",
        entities=("device:TEST-LAPTOP",),
        supporting_events=(normal_event.event_id,),
        supporting_attack_runs=(),
        observed_relationship="Shared device",
        explanation="Test graph context",
    )
    assert map_evidence([normal_event], [detection(normal_event.event_id)], (), [graph]) == ()


def test_graph_strengthens_related_sequence_to_high(event_factory) -> None:
    failed = event_factory(event_id="E1", login_success=False, failed_login_count=9)
    success = event_factory(event_id="E2", timestamp=failed.timestamp + timedelta(minutes=2), is_known_device=False)
    sequence = analyze_sequences([failed, success])
    graph = GraphFinding(
        finding_type="MULTI_USER_SUSPICIOUS_INFRASTRUCTURE",
        severity="high",
        entities=("device:TEST-LAPTOP",),
        supporting_events=("E1", "E2"),
        supporting_attack_runs=(),
        observed_relationship="Infrastructure reuse",
        explanation="Corroboration",
    )
    mappings = map_evidence(
        [failed, success],
        [detection("E1", "REPEATED_FAILED_LOGINS"), detection("E2", "UNKNOWN_DEVICE")],
        sequence,
        [graph],
    )
    assert all(item.confidence == "high" for item in mappings)


def test_informational_trusted_shared_infrastructure_does_not_strengthen(normal_event) -> None:
    graph = GraphFinding(
        finding_type="SHARED_IP",
        severity="informational",
        entities=("ip_address:10.0.0.1",),
        supporting_events=(normal_event.event_id,),
        supporting_attack_runs=(),
        observed_relationship="Trusted corporate gateway",
        explanation="Expected shared NAT",
    )
    mappings = map_evidence([normal_event], [detection(normal_event.event_id, "UNKNOWN_DEVICE")], (), [graph])
    assert mappings[0].confidence == "low"
    assert mappings[0].supporting_graph_findings == ()
