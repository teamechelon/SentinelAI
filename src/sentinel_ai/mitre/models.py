"""Typed records for ATT&CK mappings and analyst-facing threat stories."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sentinel_ai.domain import ActivityEvent, SequenceFinding
from sentinel_ai.graph import GraphFinding


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactics: tuple[str, ...]
    description: str
    source_version: str
    source_url: str


@dataclass(frozen=True)
class MitreMapping:
    technique_id: str
    technique_name: str
    tactic: str
    confidence: str
    observed_behaviour: str
    explanation: str
    supporting_event_ids: tuple[str, ...]
    supporting_rule_names: tuple[str, ...]
    supporting_sequence_findings: tuple[str, ...]
    supporting_graph_findings: tuple[str, ...]
    evidence_count: int


@dataclass(frozen=True)
class TimelineEntry:
    timestamp: datetime
    event_id: str
    activity: str
    observation: str
    risk_level: str | None


@dataclass(frozen=True)
class ThreatStory:
    title: str
    summary: str
    employee_id: str
    employee_name: str
    risk_level: str
    timeline: tuple[TimelineEntry, ...]
    key_evidence: tuple[str, ...]
    sequence_context: tuple[str, ...]
    graph_context: tuple[str, ...]
    mapped_technique_ids: tuple[str, ...]
    investigation_focus: tuple[str, ...]


@dataclass(frozen=True)
class MitreReport:
    subject_type: str
    subject_id: str
    confidence: str
    threat_story: ThreatStory
    timeline: tuple[TimelineEntry, ...]
    mappings: tuple[MitreMapping, ...]
    supporting_events: tuple[ActivityEvent, ...]
    sequence_evidence: tuple[SequenceFinding, ...]
    graph_evidence: tuple[GraphFinding, ...]
