"""Response orchestration over policy, adapter, and persistence."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4

from sentinel_ai.response.adapter import ContainmentAdapter, SimulationContainmentAdapter
from sentinel_ai.response.models import (
    AccountStatus,
    ContainmentMode,
    ContainmentState,
    ResponseAction,
    ResponseAudit,
    ResponseResult,
    SessionStatus,
    containment_status,
)
from sentinel_ai.response.policy import ResponsePolicy
from sentinel_ai.storage.database import SentinelDatabase


class ResponseActionFailed(RuntimeError):
    pass


class ResponseService:
    def __init__(
        self,
        database: SentinelDatabase,
        policy: ResponsePolicy,
        adapter: ContainmentAdapter | None = None,
    ) -> None:
        self.database = database
        self.policy = policy
        self.adapter = adapter or SimulationContainmentAdapter()

    def state(self, employee_id: str) -> ContainmentState:
        if self.database.get_employee(employee_id) is None:
            raise KeyError(f"Unknown employee: {employee_id}")
        return self.database.get_containment_state(employee_id) or ContainmentState(employee_id=employee_id)

    def history(self, employee_id: str) -> list[ResponseAudit]:
        self.state(employee_id)
        return self.database.list_response_history(employee_id)

    def evaluate_alert(self, alert_id: str) -> tuple[ContainmentState, bool]:
        alert = self.database.get_alert_row(alert_id)
        if alert is None:
            raise KeyError(f"Unknown alert: {alert_id}")
        risk_score = float(alert["risk_score"])
        decision = self.policy.evaluate(risk_score)
        if not decision.should_contain or decision.action is None or decision.reason is None:
            return self.state(str(alert["employee_id"])), False
        employee_id = str(alert["employee_id"])
        actions = (
            (ResponseAction.BLOCK_USER, ResponseAction.REVOKE_SESSIONS)
            if decision.action is ResponseAction.BLOCK_AND_REVOKE
            else (decision.action,)
        )
        state = self.state(employee_id)
        recorded = False
        for action in actions:
            state, action_recorded = self._apply(
                employee_id=employee_id,
                action=action,
                mode=ContainmentMode.AUTO,
                actor="SentinelAI Response Policy",
                reason=decision.reason,
                alert_id=alert_id,
                risk_score=risk_score,
                idempotency_key=f"AUTO:{alert_id}:{action.value}",
            )
            recorded = recorded or action_recorded
        return state, recorded

    def perform_manual_action(
        self,
        employee_id: str,
        action: ResponseAction,
        reason: str,
        actor: str = "Analyst",
        alert_id: str | None = None,
    ) -> tuple[ContainmentState, bool]:
        cleaned_reason = reason.strip()
        cleaned_actor = actor.strip()
        if not cleaned_reason:
            raise ValueError("Containment reason cannot be empty")
        if not cleaned_actor:
            raise ValueError("Containment actor cannot be empty")
        risk_score: float | None = None
        if alert_id:
            alert = self.database.get_alert_row(alert_id)
            if alert is None:
                raise KeyError(f"Unknown alert: {alert_id}")
            if str(alert["employee_id"]) != employee_id:
                raise ValueError("Alert does not belong to the requested employee")
            risk_score = float(alert["risk_score"])
        return self._apply(
            employee_id=employee_id,
            action=action,
            mode=ContainmentMode.MANUAL,
            actor=cleaned_actor,
            reason=cleaned_reason,
            alert_id=alert_id,
            risk_score=risk_score,
        )

    def _apply(
        self,
        *,
        employee_id: str,
        action: ResponseAction,
        mode: ContainmentMode,
        actor: str,
        reason: str,
        alert_id: str | None,
        risk_score: float | None,
        idempotency_key: str | None = None,
    ) -> tuple[ContainmentState, bool]:
        current = self.state(employee_id)
        now = datetime.now(timezone.utc)
        try:
            account, sessions = self.adapter.apply(current, action)
        except Exception as error:
            audit = self._audit(
                employee_id, action, mode, actor, alert_id, risk_score, reason,
                ResponseResult.FAILED, now, "Simulation adapter could not apply the action.",
            )
            self.database.insert_response_audit(audit, idempotency_key)
            raise ResponseActionFailed("Containment action could not be completed.") from error

        if account is current.account_status and sessions is current.session_status:
            return current, False

        status = containment_status(account, sessions)
        contained_at = None if status.value == "NONE" else (current.contained_at or now)
        updated = replace(
            current,
            account_status=account,
            session_status=sessions,
            containment_status=status,
            containment_mode=mode,
            contained_at=contained_at,
            contained_by=actor,
            reason=reason,
            source_alert_id=alert_id,
            risk_score_at_action=risk_score,
            last_action=action,
            updated_at=now,
        )
        audit = self._audit(
            employee_id, action, mode, actor, alert_id, risk_score, reason,
            ResponseResult.SUCCESS, now,
        )
        inserted = self.database.persist_response_transition(updated, audit, idempotency_key)
        return (updated if inserted else self.state(employee_id)), inserted

    @staticmethod
    def _audit(
        employee_id: str,
        action: ResponseAction,
        mode: ContainmentMode,
        actor: str,
        alert_id: str | None,
        risk_score: float | None,
        reason: str,
        result: ResponseResult,
        created_at: datetime,
        detail: str | None = None,
    ) -> ResponseAudit:
        return ResponseAudit(
            action_id=f"RSP-{uuid4().hex[:16].upper()}",
            employee_id=employee_id,
            action=action,
            mode=mode,
            actor=actor,
            alert_id=alert_id,
            risk_score_at_action=risk_score,
            reason=reason,
            result=result,
            detail=detail,
            created_at=created_at,
        )
