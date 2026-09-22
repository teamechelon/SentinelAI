"""Threat-story construction from ordered, persisted evidence."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sentinel_ai.domain import ActivityEvent, SequenceFinding
from sentinel_ai.graph import GraphFinding
from sentinel_ai.mitre.mapper import map_evidence
from sentinel_ai.mitre.models import MitreReport, ThreatStory, TimelineEntry


_RISK_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def _observation(event: ActivityEvent) -> str:
    if event.activity_type == "login":
        outcome = "successful" if event.login_success else "failed"
        context = "unknown device" if not event.is_known_device else "known device"
        return f"{outcome.title()} login from {event.city}, {event.country} using {context}; {event.failed_login_count} recent failures recorded."
    if event.current_privilege != event.previous_privilege:
        return f"Privilege changed from {event.previous_privilege} to {event.current_privilege}."
    if event.activity_type == "file_access":
        return f"Accessed {event.file_sensitivity.lower()} resource {event.file_name or 'unnamed resource'}."
    if event.activity_type == "download":
        return f"Downloaded {event.download_count} items totaling {event.download_size_mb:.1f} MB."
    return f"Observed {event.activity_type.replace('_', ' ')} activity."


def build_report(
    subject_type: str,
    subject_id: str,
    events: Iterable[ActivityEvent],
    detection_rows: Iterable[dict[str, Any]],
    sequence_findings: Iterable[SequenceFinding] = (),
    graph_findings: Iterable[GraphFinding] = (),
) -> MitreReport:
    ordered_events = tuple(sorted(events, key=lambda item: (item.timestamp, item.event_id)))
    rows = tuple(detection_rows)
    sequences = tuple(sequence_findings)
    graphs = tuple(graph_findings)
    mappings = map_evidence(ordered_events, rows, sequences, graphs)
    row_by_event = {str(row.get("event_id")): row for row in rows}
    timeline = tuple(TimelineEntry(
        timestamp=event.timestamp,
        event_id=event.event_id,
        activity=event.activity_type.replace("_", " ").title(),
        observation=_observation(event),
        risk_level=str(row_by_event[event.event_id]["risk_level"]) if event.event_id in row_by_event and row_by_event[event.event_id].get("risk_level") else None,
    ) for event in ordered_events)
    risk_levels = [entry.risk_level for entry in timeline if entry.risk_level]
    risk_level = max(risk_levels, key=lambda item: _RISK_ORDER.get(item, -1)) if risk_levels else "Low"
    employee_id = ordered_events[0].employee_id if ordered_events else "Unknown"
    employee_name = ordered_events[0].employee_name if ordered_events else "Unknown employee"
    technique_names = [mapping.technique_name for mapping in mappings]
    title = f"{employee_name}: {' → '.join(technique_names)}" if technique_names else f"{employee_name}: no ATT&CK mapping"
    summary = (
        f"{len(ordered_events)} ordered event(s) produced {len(mappings)} evidence-backed ATT&CK mapping(s): {', '.join(technique_names)}."
        if mappings else
        f"{len(ordered_events)} event(s) were reviewed; current rule and sequence evidence does not justify an ATT&CK mapping."
    )
    key_evidence = tuple(dict.fromkeys(
        [mapping.observed_behaviour for mapping in mappings]
        + [f"{finding.code}: {finding.title}" for finding in sequences]
    ))
    investigation_focus = tuple(dict.fromkeys(
        [f"Validate the account owner and origin of events supporting {mapping.technique_id} {mapping.technique_name}." for mapping in mappings]
        + (["Review the ordered event timeline for additional direct behavioural evidence."] if not mappings else [])
    ))
    confidence_order = {"low": 0, "medium": 1, "high": 2}
    confidence = max((mapping.confidence for mapping in mappings), key=lambda item: confidence_order[item], default="none")
    story = ThreatStory(
        title=title,
        summary=summary,
        employee_id=employee_id,
        employee_name=employee_name,
        risk_level=risk_level,
        timeline=timeline,
        key_evidence=key_evidence,
        sequence_context=tuple(dict.fromkeys(f"{finding.code}: {finding.title}" for finding in sequences)),
        graph_context=tuple(dict.fromkeys(f"{finding.finding_type}: {finding.observed_relationship}" for finding in graphs)),
        mapped_technique_ids=tuple(mapping.technique_id for mapping in mappings),
        investigation_focus=investigation_focus,
    )
    return MitreReport(
        subject_type=subject_type,
        subject_id=subject_id,
        confidence=confidence,
        threat_story=story,
        timeline=timeline,
        mappings=mappings,
        supporting_events=ordered_events,
        sequence_evidence=sequences,
        graph_evidence=graphs,
    )
