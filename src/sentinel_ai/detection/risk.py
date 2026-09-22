"""Deterministic hybrid risk scoring and explanation assembly."""

from __future__ import annotations

from datetime import datetime, timezone

from sentinel_ai import config
from sentinel_ai.domain import ActivityEvent, DetectionResult, FeatureVector, ModelScore, RuleHit


def risk_level(score: float) -> str:
    for minimum, label in config.RISK_BANDS:
        if score >= minimum:
            return label
    return "Low"


def contextual_severity(rule_hits: tuple[RuleHit, ...]) -> float:
    codes = {hit.rule_name for hit in rule_hits}
    contribution = 5.0 if len(codes) >= 2 else 0.0
    if {"REPEATED_FAILED_LOGINS", "UNKNOWN_DEVICE"}.issubset(codes) or {"REPEATED_FAILED_LOGINS", "UNUSUAL_LOCATION"}.issubset(codes):
        contribution += 5.0
    if "PRIVILEGE_ESCALATION" in codes and ({"BULK_DOWNLOAD", "LARGE_DOWNLOAD", "SENSITIVE_FILE_ACCESS"} & codes):
        contribution += 5.0
    if len(codes) >= 5:
        contribution += 5.0
    return min(config.CONTEXT_MAX_CONTRIBUTION, contribution)


def recommended_response(level: str) -> str:
    responses = {
        "Low": "Retain the event and continue routine monitoring.",
        "Medium": "Review the evidence and verify the employee context; simulate step-up authentication if unexplained.",
        "High": "Prioritize SOC investigation, contact the employee, and simulate restricting the suspicious session.",
        "Critical": "Escalate immediately and simulate account containment while preserving evidence. No destructive action is executed.",
    }
    return responses[level]


def combine_risk(
    event: ActivityEvent,
    features: FeatureVector,
    rule_hits: tuple[RuleHit, ...],
    model_score: ModelScore,
) -> DetectionResult:
    rule_contribution = round(sum(hit.contribution for hit in rule_hits), 2)
    context_contribution = contextual_severity(rule_hits)
    final_score = round(min(100.0, rule_contribution + model_score.contribution + context_contribution), 2)
    level = risk_level(final_score)
    if rule_hits:
        reason_text = "; ".join(f"{hit.rule_name} (+{hit.contribution:g}): {hit.reason}" for hit in rule_hits)
    else:
        reason_text = "No deterministic threat rule fired."
    model_text = (
        f"AI nonconformity ranked at the {model_score.anomaly_percentile:.2f} percentile and contributed {model_score.contribution:.2f}."
        if model_score.anomaly_percentile is not None
        else f"AI model status is {model_score.status}; contribution is 0."
    )
    context_text = f" Context correlation contributed {context_contribution:.2f}." if context_contribution else ""
    explanation = f"{reason_text} {model_text}{context_text} Final score: {final_score:.2f}/100 ({level})."
    return DetectionResult(
        detection_id=f"DET-{event.event_id}",
        event_id=event.event_id,
        employee_id=event.employee_id,
        detected_at=datetime.now(timezone.utc),
        final_risk_score=final_score,
        risk_level=level,
        rule_contribution=rule_contribution,
        ai_contribution=model_score.contribution,
        contextual_contribution=context_contribution,
        triggered_rules=rule_hits,
        explanation=explanation,
        recommended_response=recommended_response(level),
        model_status=model_score.status,
        model_raw_score=model_score.raw_score,
        anomaly_percentile=model_score.anomaly_percentile,
        feature_values=features.as_mapping(),
    )

