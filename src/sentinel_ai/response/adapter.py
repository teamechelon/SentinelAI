"""Containment adapter boundary and the internal simulation implementation."""

from __future__ import annotations

from typing import Protocol

from sentinel_ai.response.models import AccountStatus, ContainmentState, ResponseAction, SessionStatus


class ContainmentAdapter(Protocol):
    name: str

    def apply(self, state: ContainmentState, action: ResponseAction) -> tuple[AccountStatus, SessionStatus]: ...


class SimulationContainmentAdapter:
    """Changes only SentinelAI's internal state; performs no external calls."""

    name = "SentinelAI Simulation"

    def apply(self, state: ContainmentState, action: ResponseAction) -> tuple[AccountStatus, SessionStatus]:
        account = state.account_status
        sessions = state.session_status
        if action is ResponseAction.BLOCK_USER:
            account = AccountStatus.BLOCKED
        elif action is ResponseAction.UNBLOCK_USER:
            account = AccountStatus.ACTIVE
        elif action is ResponseAction.REVOKE_SESSIONS:
            sessions = SessionStatus.REVOKED
        elif action is ResponseAction.RESTORE_SESSIONS:
            sessions = SessionStatus.ACTIVE
        elif action is ResponseAction.BLOCK_AND_REVOKE:
            account = AccountStatus.BLOCKED
            sessions = SessionStatus.REVOKED
        return account, sessions
