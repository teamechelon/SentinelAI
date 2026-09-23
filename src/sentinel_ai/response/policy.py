"""Central automatic-response decision policy."""

from __future__ import annotations

from sentinel_ai.response.models import PolicyDecision, ResponseAction


class ResponsePolicy:
    def __init__(self, enabled: bool, risk_threshold: float) -> None:
        self.enabled = enabled
        self.risk_threshold = risk_threshold

    def evaluate(self, risk_score: float) -> PolicyDecision:
        if not self.enabled or risk_score < self.risk_threshold:
            return PolicyDecision(False, None, None)
        return PolicyDecision(
            True,
            ResponseAction.BLOCK_AND_REVOKE,
            "Automatic containment triggered because production risk score reached "
            f"the configured threshold of {self.risk_threshold:g}.",
        )
