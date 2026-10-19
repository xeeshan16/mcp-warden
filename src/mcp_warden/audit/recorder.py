"""Turning the proxy's view of a request into audit events, and storing them.

The recorder is deliberately fail-open: a call that the gateway has already
answered is not turned into an error because the audit write failed. Failed
writes are logged and counted (``failed_writes``) so that monitoring can
alert on them; the metrics endpoint exposes the counter on day 11.

Events of one HTTP request (one message, or every entry of a batch) are
written in a single transaction.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import anyio.to_thread

from mcp_warden.audit.model import ArgumentHasher, AuditEvent, Outcome, outcome_for_refusal
from mcp_warden.audit.store import AuditStore
from mcp_warden.jsonrpc import JsonRpcError, JsonRpcErrorResponse, JsonRpcSuccess

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(slots=True)
class Trace:
    """What the proxy learns about one request while handling it."""

    agent: str
    server: str
    method: str
    occurred_at: datetime
    started: float
    tool: str | None = None
    effect: str | None = None
    rule_id: str | None = None
    approval_id: str | None = None
    arguments_digest: str | None = None
    arguments_size: int | None = None

    def note_refusal_data(self, data: Any) -> None:
        """Pick the rule and approval ids (never anything else) out of error data."""
        if not isinstance(data, dict):
            return
        rule_id, approval_id = data.get("rule_id"), data.get("approval_id")
        effect = data.get("effect")
        if self.rule_id is None and isinstance(rule_id, str):
            self.rule_id = rule_id
        if self.approval_id is None and isinstance(approval_id, str):
            self.approval_id = approval_id
        if self.effect is None and isinstance(effect, str):
            self.effect = effect


class AuditRecorder:
    def __init__(
        self,
        store: AuditStore,
        hasher: ArgumentHasher | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
        timer: Callable[[], float] = time.perf_counter,
    ) -> None:
        self.store = store
        self.hasher = hasher or ArgumentHasher()
        self._clock = clock or _utcnow
        self._timer = timer
        self.failed_writes = 0

    def start(self, agent: str, server: str, method: str) -> Trace:
        return Trace(agent, server, method, self._clock(), self._timer())

    def note_arguments(self, trace: Trace, tool: str, arguments: dict[str, Any]) -> None:
        trace.tool = tool
        trace.arguments_digest, trace.arguments_size = self.hasher.digest(arguments)

    def answered(
        self, trace: Trace, response: JsonRpcSuccess | JsonRpcErrorResponse | None
    ) -> AuditEvent:
        """The upstream answered (possibly with an error of its own)."""
        error_code: int | None = None
        tool_error: bool | None = None
        if isinstance(response, JsonRpcErrorResponse):
            error_code = response.error.code
        elif isinstance(response, JsonRpcSuccess) and trace.tool is not None:
            result = response.result
            tool_error = isinstance(result, dict) and result.get("isError") is True
        return self._event(trace, Outcome.FORWARDED, error_code, tool_error)

    def refused(self, trace: Trace, error: JsonRpcError) -> AuditEvent:
        """The gateway answered with ``error`` (its own refusal or an upstream failure)."""
        trace.note_refusal_data(error.data)
        return self._event(trace, outcome_for_refusal(error.code), error.code, None)

    def failed(self, trace: Trace, outcome: Outcome) -> AuditEvent:
        """The request ended without a JSON-RPC answer (e.g. the upstream lost the session)."""
        return self._event(trace, outcome, None, None)

    async def write(self, events: Sequence[AuditEvent]) -> None:
        if not events:
            return
        try:
            await anyio.to_thread.run_sync(self.store.append, list(events))
        except Exception:
            self.failed_writes += 1
            logger.exception("failed to write %d audit event(s)", len(events))

    def _event(
        self, trace: Trace, outcome: Outcome, error_code: int | None, tool_error: bool | None
    ) -> AuditEvent:
        return AuditEvent.create(
            occurred_at=trace.occurred_at,
            agent=trace.agent,
            server=trace.server,
            method=trace.method,
            outcome=outcome,
            latency_ms=(self._timer() - trace.started) * 1000,
            tool=trace.tool,
            effect=trace.effect,
            rule_id=trace.rule_id,
            approval_id=trace.approval_id,
            error_code=error_code,
            tool_error=tool_error,
            arguments_digest=trace.arguments_digest,
            arguments_size=trace.arguments_size,
        )
