"""Deterministic ATT&CK mapping from direct SentinelAI evidence."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from sentinel_ai.domain import ActivityEvent, SequenceFinding
from sentinel_ai.graph import GraphFinding
from sentinel_ai.mitre.catalog import get_technique
from sentinel_ai.mitre.models import MitreMapping


_RULE_TECHNIQUES = {
    "REPEATED_FAILED_LOGINS": "T1110",
    "UNKNOWN_DEVICE": "T1078",
    "UNUSUAL_LOCATION": "T1078",
    "IMPOSSIBLE_TRAVEL": "T1078",
    "PRIVILEGE_ESCALATION": "T1098",
    "SENSITIVE_FILE_ACCESS": "T1005",
}

_SEQUENCE_TECHNIQUES = {
    "BRUTE_FORCE_SUCCESS": ("T1110", "T1078"),
    "ACCOUNT_COMPROMISE": ("T1110", "T1078", "T1005"),
    "PRIVILEGE_ABUSE": ("T1098", "T1005"),
    "POSSIBLE_EXFILTRATION": ("T1005",),
}

_BEHAVIOURS = {
    "T1110": "Repeated authentication failures",
    "T1078": "Successful account use from an anomalous access context",
    "T1098": "Observed account privilege change",
    "T1005": "Observed access to sensitive local data",
}


def _confidence(event_ids: set[str], rules: set[str], sequences: set[str], graphs: set[str]) -> str:
    """One confidence policy used for every mapping.

    High requires direct rule evidence, ordered sequence corroboration, graph
    corroboration, and multiple events. Medium requires an ordered sequence or
    multiple independent direct observations. A lone direct rule is low.
    """

    if rules and sequences and graphs and len(event_ids) >= 2:
        return "high"
    if sequences or len(rules) >= 2 or len(event_ids) >= 2:
        return "medium"
    return "low"


def map_evidence(
    events: Iterable[ActivityEvent],
    detection_rows: Iterable[dict[str, Any]],
    sequence_findings: Iterable[SequenceFinding] = (),
    graph_findings: Iterable[GraphFinding] = (),
) -> tuple[MitreMapping, ...]:
    """Return mappings only when direct rule or sequence evidence exists.

    Model score, final risk, scenario labels, and graph evidence never originate
    a mapping. Graph findings may only corroborate a mapping already supported by
    a rule or an ordered sequence and sharing one of its events.
    """

    ordered_events = sorted(events, key=lambda item: (item.timestamp, item.event_id))
    available_ids = {event.event_id for event in ordered_events}
    event_ids: dict[str, set[str]] = defaultdict(set)
    rules: dict[str, set[str]] = defaultdict(set)
    sequences: dict[str, set[str]] = defaultdict(set)
    graphs: dict[str, set[str]] = defaultdict(set)

    for row in detection_rows:
        current_event_id = str(row.get("event_id", ""))
        if current_event_id not in available_ids:
            continue
        for rule in row.get("triggered_rules", []):
            rule_name = str(rule.get("rule_name", ""))
            technique_id = _RULE_TECHNIQUES.get(rule_name)
            if technique_id:
                event_ids[technique_id].add(current_event_id)
                rules[technique_id].add(rule_name)

    for finding in sequence_findings:
        for technique_id in _SEQUENCE_TECHNIQUES.get(finding.code, ()):
            matched_ids = available_ids.intersection(finding.event_ids)
            if matched_ids:
                event_ids[technique_id].update(matched_ids)
                sequences[technique_id].add(finding.code)

    # Corroboration only: informational shared infrastructure and unrelated
    # graph relationships are deliberately excluded.
    for technique_id, supported_ids in event_ids.items():
        if not (rules[technique_id] or sequences[technique_id]):
            continue
        for finding in graph_findings:
            if finding.severity in {"medium", "high", "critical"} and supported_ids.intersection(finding.supporting_events):
                graphs[technique_id].add(finding.finding_type)

    mappings: list[MitreMapping] = []
    for technique_id in ("T1110", "T1078", "T1098", "T1005"):
        if not event_ids[technique_id] or not (rules[technique_id] or sequences[technique_id]):
            continue
        technique = get_technique(technique_id)
        ids = event_ids[technique_id]
        rule_names = rules[technique_id]
        sequence_names = sequences[technique_id]
        graph_names = graphs[technique_id]
        confidence = _confidence(ids, rule_names, sequence_names, graph_names)
        corroboration = []
        if sequence_names:
            corroboration.append(f"ordered sequence evidence ({', '.join(sorted(sequence_names))})")
        if graph_names:
            corroboration.append(f"related graph evidence ({', '.join(sorted(graph_names))})")
        suffix = f" Corroborated by {' and '.join(corroboration)}." if corroboration else ""
        mappings.append(MitreMapping(
            technique_id=technique.technique_id,
            technique_name=technique.name,
            tactic=technique.tactics[0],
            confidence=confidence,
            observed_behaviour=_BEHAVIOURS[technique_id],
            explanation=f"Mapped from explicit {', '.join(sorted(rule_names)) or 'sequence'} evidence across {len(ids)} supporting event(s).{suffix}",
            supporting_event_ids=tuple(sorted(ids)),
            supporting_rule_names=tuple(sorted(rule_names)),
            supporting_sequence_findings=tuple(sorted(sequence_names)),
            supporting_graph_findings=tuple(sorted(graph_names)),
            evidence_count=len(ids) + len(rule_names) + len(sequence_names) + len(graph_names),
        ))
    return tuple(mappings)
