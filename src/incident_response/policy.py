"""Deterministic incident policy. The adapter owns all database and demo operations.

Only four fixed inspections are available. No fetched page text, log message,
URL, secret, model output, shell command, or arbitrary tool enters the policy.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Literal, Mapping, Protocol, Sequence
from uuid import UUID


POLICY = "fixed_responder_v1"
INSPECTIONS = ("get_worker_health", "get_failed_run", "get_recent_errors", "get_queue_depth")
ALERT_KINDS = frozenset({"repeated_run_failure", "worker_queue_stalled"})
TARGET_ERRORS = frozenset({"HTTP_STATUS_ERROR", "DNS_ERROR", "FETCH_TIMEOUT",
                           "FETCH_ERROR", "DESTINATION_BLOCKED"})
SAFE_ERROR_CODES = TARGET_ERRORS | frozenset({
    "WORKER_INTERRUPTED", "URL_INVALID", "RESPONSE_TOO_LARGE", "UNSUPPORTED_CONTENT_TYPE",
    "UNSUPPORTED_CHARSET", "INSUFFICIENT_CONTENT", "EXTRACTION_ERROR", "LLM_ERROR",
    "MODEL_PROVIDER_UNAVAILABLE", "HANDLER_ERROR", "HANDLER_UNAVAILABLE",
})
SAFE_LOG_EVENTS = frozenset({
    "RUN_QUEUED", "RUN_CLAIMED", "RUN_STARTED", "RUN_SUCCEEDED", "RUN_FAILED",
    "DEMO_WORKER_PAUSED", "DEMO_WORKER_RESUMED", "HTTP_REQUEST_FAILED",
    "HTTP_STATUS_ERROR", "DNS_ERROR", "DESTINATION_BLOCKED", "FETCH_TIMEOUT",
    "FETCH_ERROR", "RESPONSE_TOO_LARGE", "WORKER_INTERRUPTED", "LLM_REQUEST_FAILED",
    "MODEL_PROVIDER_UNAVAILABLE", "HANDLER_ERROR",
})
_TRACE = re.compile(r"[0-9a-fA-F]{32}")


def _uuid(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(UUID(value))
    except ValueError:
        return None


def _trace(value: object) -> str | None:
    return value.lower() if isinstance(value, str) and _TRACE.fullmatch(value) else None


@dataclass(frozen=True)
class Alert:
    id: str
    owner_id: str
    run_id: str
    run_owner_id: str
    kind: str
    status: str
    run_status: str
    trace_id: str | None = None


@dataclass(frozen=True)
class QueueDepth:
    owned_queued: int
    total_active: int


@dataclass(frozen=True)
class IncidentDraft:
    alert_id: str
    owner_id: str
    run_id: str
    trace_id: str | None
    evidence: Mapping[str, object]
    symptom: str
    likely_cause: str
    recommendation: str
    decision_source: str
    action: Literal["none", "resume_demo_worker"]
    decision: Literal["action_denied", "approval_required", "reserved"]
    reason: str
    before_status: str


@dataclass(frozen=True)
class Reservation:
    incident_id: str
    created: bool
    decision: str


@dataclass(frozen=True)
class RecoveryState:
    run_status: str | None
    alert_status: str | None


class ResponderAdapter(Protocol):
    """RunGuard supplies persistence and the exact demo gate; the policy never does I/O."""

    def open_alerts(self) -> Sequence[tuple[str, str]]: ...
    def get_owned_alert(self, alert_id: str, owner_id: str) -> Alert | None: ...
    def get_incident(self, alert_id: str, owner_id: str) -> dict | None: ...
    def get_worker_health(self) -> Mapping[str, object]: ...
    def get_failed_run(self, owner_id: str, run_id: str) -> Mapping[str, object] | None: ...
    def get_recent_errors(self, owner_id: str, run_id: str) -> Sequence[Mapping[str, object]]: ...
    def get_queue_depth(self, owner_id: str) -> QueueDepth: ...
    def demo_gate(self, alert: Alert) -> Literal["outside_demo", "mismatch", "passed"]: ...
    def reserve_incident(self, draft: IncidentDraft) -> Reservation: ...
    def resume_demo_worker(self, alert: Alert) -> bool: ...
    def recovery_state(self, alert: Alert) -> RecoveryState: ...
    def record_outcome(self, incident_id: str, *, decision: str, reason: str,
                       result: str, after_status: str | None) -> None: ...
    def read_incident(self, incident_id: str, owner_id: str) -> dict: ...


class Responder:
    def __init__(self, adapter: ResponderAdapter, *, recovery_timeout: float = 35,
                 sleep=time.sleep, clock=time.monotonic):
        self.adapter = adapter
        self.recovery_timeout = recovery_timeout
        self.sleep = sleep
        self.clock = clock

    def respond(self, alert_id: str, owner_id: str) -> dict | None:
        """Diagnose one owned alert; reserve at most one audited demo action."""
        alert = self.adapter.get_owned_alert(alert_id, owner_id)
        if (alert is None or alert.owner_id != owner_id or alert.run_owner_id != owner_id
                or alert.kind not in ALERT_KINDS):
            return None
        existing = self.adapter.get_incident(alert.id, owner_id)
        if existing is not None:
            return existing
        if alert.status != "open" or _uuid(alert.id) is None or _uuid(alert.run_id) is None:
            return None

        health = self.adapter.get_worker_health()
        failed = self.adapter.get_failed_run(owner_id, alert.run_id)
        errors = self.adapter.get_recent_errors(owner_id, alert.run_id)
        depth = self.adapter.get_queue_depth(owner_id)
        error_code = (failed or {}).get("error_code")
        if not isinstance(error_code, str) or error_code not in SAFE_ERROR_CODES:
            error_code = "HANDLER_ERROR" if failed else None
        safe_rows = []
        for row in errors[:10]:
            log_id = row.get("log_id")
            run_id = _uuid(row.get("run_id"))
            event = row.get("event")
            if isinstance(log_id, int) and log_id > 0 and run_id:
                safe_rows.append({"log_id": log_id, "run_id": run_id,
                                  "event": (event if isinstance(event, str) and event in SAFE_LOG_EVENTS
                                            else "HANDLER_ERROR")})
        evidence = {"inspection_names": list(INSPECTIONS), "alert_id": alert.id,
                    "run_id": alert.run_id, "trace_id": _trace(alert.trace_id),
                    "log_ids": [row["log_id"] for row in safe_rows],
                    "error_run_ids": [row["run_id"] for row in safe_rows],
                    "log_events": [row["event"] for row in safe_rows],
                    "error_code": error_code,
                    "queue_depth": max(0, int(depth.owned_queued)),
                    "worker_healthy": health.get("healthy") is True}

        if alert.kind == "worker_queue_stalled":
            cause = "worker_queue_stalled"
            symptom = "A run is queued while the worker is unhealthy."
            recommendation = "Inspect the worker heartbeat and resume the isolated demo worker if authorized."
        elif error_code in TARGET_ERRORS:
            cause = "target_site_failure"
            symptom = "Repeated configured-target checks failed."
            recommendation = "Inspect the target and run logs; a user may retry manually."
        else:
            cause = "job_execution_failure"
            symptom = "Repeated jobs failed in RunGuard."
            recommendation = "Inspect worker and run logs; a user may retry manually."

        decision, reason = "action_denied", "manual_retry_only"
        if alert.kind == "worker_queue_stalled":
            decision, reason = "approval_required", "outside_demo"
            gate = self.adapter.demo_gate(alert)
            if gate == "mismatch":
                decision, reason = "action_denied", "demo_binding_mismatch"
            elif (gate == "passed" and alert.run_status == "queued"
                  and depth.owned_queued == 1 and depth.total_active == 1):
                decision, reason = "reserved", "demo_gate_passed"
            elif gate == "passed":
                decision, reason = "action_denied", "demo_binding_mismatch"

        draft = IncidentDraft(alert_id=alert.id, owner_id=owner_id, run_id=alert.run_id,
                              trace_id=_trace(alert.trace_id), evidence=evidence,
                              symptom=symptom, likely_cause=cause,
                              recommendation=recommendation, decision_source=POLICY,
                              action="resume_demo_worker" if alert.kind == "worker_queue_stalled" else "none",
                              decision=decision, reason=reason, before_status=alert.run_status)
        reservation = self.adapter.reserve_incident(draft)
        if not reservation.created:
            return self.adapter.read_incident(reservation.incident_id, owner_id)
        if decision == "reserved" and reservation.decision == "reserved":
            self._resume_and_verify(reservation.incident_id, alert)
        return self.adapter.read_incident(reservation.incident_id, owner_id)

    def _resume_and_verify(self, incident_id: str, alert: Alert) -> None:
        try:
            resumed = self.adapter.resume_demo_worker(alert)
        except Exception:
            resumed = False
        if not resumed:
            state = self._safe_recovery_state(alert)
            self.adapter.record_outcome(incident_id, decision="action_denied",
                                        reason="demo_gate_changed", result="denied",
                                        after_status=state.run_status)
            return
        deadline = self.clock() + self.recovery_timeout
        while self.clock() < deadline:
            state = self._safe_recovery_state(alert)
            if (state.run_status not in {None, "queued", "running"}
                    and state.alert_status == "resolved"):
                result = "recovered" if state.run_status == "succeeded" else "run_failed"
                self.adapter.record_outcome(incident_id, decision="executed",
                                            reason="demo_gate_passed", result=result,
                                            after_status=state.run_status)
                return
            self.sleep(0.5)
        state = self._safe_recovery_state(alert)
        self.adapter.record_outcome(incident_id, decision="executed",
                                    reason="demo_gate_passed", result="recovery_timeout",
                                    after_status=state.run_status)

    def _safe_recovery_state(self, alert: Alert) -> RecoveryState:
        try:
            return self.adapter.recovery_state(alert)
        except Exception:
            return RecoveryState(run_status=None, alert_status=None)

    def run_open_once(self) -> list[dict]:
        """Only persisted open alerts trigger an incident."""
        return [result for alert_id, owner_id in self.adapter.open_alerts()
                if (result := self.respond(alert_id, owner_id)) is not None]
