"""Typed state and audit records for simulated containment."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class AccountStatus(StrEnum):
    ACTIVE = "ACTIVE"
    BLOCKED = "BLOCKED"


class SessionStatus(StrEnum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"


class ContainmentStatus(StrEnum):
    NONE = "NONE"
    PARTIAL = "PARTIAL"
    CONTAINED = "CONTAINED"


class ContainmentMode(StrEnum):
    AUTO = "AUTO"
    MANUAL = "MANUAL"


class ResponseAction(StrEnum):
    BLOCK_USER = "BLOCK_USER"
    UNBLOCK_USER = "UNBLOCK_USER"
    REVOKE_SESSIONS = "REVOKE_SESSIONS"
    RESTORE_SESSIONS = "RESTORE_SESSIONS"
    BLOCK_AND_REVOKE = "BLOCK_AND_REVOKE"


class ResponseResult(StrEnum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


@dataclass(frozen=True)
class ContainmentState:
    employee_id: str
    account_status: AccountStatus = AccountStatus.ACTIVE
    session_status: SessionStatus = SessionStatus.ACTIVE
    containment_status: ContainmentStatus = ContainmentStatus.NONE
    containment_mode: ContainmentMode | None = None
    contained_at: datetime | None = None
    contained_by: str | None = None
    reason: str | None = None
    source_alert_id: str | None = None
    risk_score_at_action: float | None = None
    last_action: ResponseAction | None = None
    updated_at: datetime | None = None


@dataclass(frozen=True)
class ResponseAudit:
    action_id: str
    employee_id: str
    action: ResponseAction
    mode: ContainmentMode
    actor: str
    alert_id: str | None
    risk_score_at_action: float | None
    reason: str
    result: ResponseResult
    created_at: datetime
    detail: str | None = None


@dataclass(frozen=True)
class PolicyDecision:
    should_contain: bool
    action: ResponseAction | None
    reason: str | None


def containment_status(account: AccountStatus, sessions: SessionStatus) -> ContainmentStatus:
    if account is AccountStatus.ACTIVE and sessions is SessionStatus.ACTIVE:
        return ContainmentStatus.NONE
    if account is AccountStatus.BLOCKED and sessions is SessionStatus.REVOKED:
        return ContainmentStatus.CONTAINED
    return ContainmentStatus.PARTIAL
