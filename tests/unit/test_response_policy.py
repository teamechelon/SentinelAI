"""Response policy consumes persisted risk without recalculating it."""

from sentinel_ai.response.models import ResponseAction
from sentinel_ai.response.policy import ResponsePolicy


def test_policy_contains_only_at_configured_threshold() -> None:
    policy = ResponsePolicy(enabled=True, risk_threshold=100)

    assert policy.evaluate(99.99).should_contain is False
    decision = policy.evaluate(100)
    assert decision.should_contain is True
    assert decision.action is ResponseAction.BLOCK_AND_REVOKE
    assert "threshold of 100" in decision.reason


def test_disabled_policy_never_contains() -> None:
    assert ResponsePolicy(enabled=False, risk_threshold=100).evaluate(100).should_contain is False
