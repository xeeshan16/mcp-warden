"""The proxy pipeline for one ``POST /mcp/{server}`` call.

Responsibilities, in order:

1. authenticate the agent (see :mod:`mcp_warden.identity`); nothing else,
   not even whether a server exists, is revealed to an unauthenticated caller;
2. resolve the upstream by name (unknown servers never reach the network);
3. parse the payload with the hardened parser; batches are accepted only when
   the client declared an MCP revision that still allowed them;
4. handle each message: ``tools/call`` is checked against the policy, then
   the approval gate (for ``require_approval``), then the rate limits, then
   the budgets before it is forwarded (a denied or still-pending call never
   spends a token, a rate-limited call never spends budget, and an approval
   is spent only by a call that is actually forwarded), and the reply's
   tokens are booked against the budgets once it arrives;
   ``tools/list`` results are filtered on the way back, other
   requests are forwarded and answered, notifications and client responses
   are forwarded and acknowledged with ``202``;
5. record one metadata-only event per request (see :mod:`mcp_warden.audit`);
   the events of one HTTP request feed the metrics and, when an audit store
   is configured, are written together once every entry has been answered;
6. map every refusal and upstream failure onto a JSON-RPC error carrying the
   request id. A single rate-limited, over-budget or pending-approval call
   also gets a ``Retry-After`` header;
   the HTTP status stays ``200`` because MCP clients read the JSON-RPC error.

Each request is also an OpenTelemetry span (``tools/call <tool>``, kind
``SERVER``) whose parent is the trace context the agent sent, with child spans
for the stages that can wait (approval, rate limit, budget) and for the
upstream leg (see :mod:`mcp_warden.proxy.instrumented`).

Batch entries are forwarded one by one (concurrently) rather than as a batch.
That keeps per-call checks — policy, rate limits, budgets from the following
milestones — independent of how the agent packaged its calls, and means an
upstream never sees a batch it might not support.

Only ``Mcp-Session-Id`` and ``MCP-Protocol-Version`` cross the gateway from
the agent. The agent's own credentials (``Authorization`` and the like) are
for the gateway, never for the upstream; upstream credentials come from the
upstream registry.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from typing import Any

from opentelemetry import context as otel_context
from opentelemetry.trace import Span, SpanKind, Status, StatusCode, Tracer

from mcp_warden.approval import ApprovalGate
from mcp_warden.audit import AuditEvent, AuditRecorder, Outcome
from mcp_warden.audit.recorder import Trace
from mcp_warden.budget import BudgetEnforcer, Reservation
from mcp_warden.identity import AuthenticationError, Authenticator
from mcp_warden.jsonrpc import (
    ErrorCode,
    InvalidMessage,
    JsonRpcError,
    JsonRpcErrorResponse,
    JsonRpcRequest,
    JsonRpcSuccess,
    ParsedItem,
    ParseLimits,
    RetryAfterError,
    error_response,
    error_response_from,
    parse_payload,
    to_wire,
)
from mcp_warden.jsonrpc.mcp import Method, batching_allowed, parse_call_tool
from mcp_warden.observability.metrics import GatewayMetrics
from mcp_warden.observability.tracing import (
    ATTR_AGENT,
    ATTR_APPROVAL,
    ATTR_EFFECT,
    ATTR_ERROR_TYPE,
    ATTR_JSONRPC_ERROR,
    ATTR_METHOD,
    ATTR_OPERATION,
    ATTR_OUTCOME,
    ATTR_PROTOCOL_VERSION,
    ATTR_RULE,
    ATTR_SERVER,
    ATTR_TOOL,
    ATTR_TOOL_ERROR,
    extract_context,
    tracer_from,
)
from mcp_warden.policy import Effect
from mcp_warden.proxy.client import (
    PROTOCOL_HEADER,
    SESSION_HEADER,
    UpstreamResponse,
    UpstreamSessionNotFoundError,
    UpstreamTransport,
)
from mcp_warden.proxy.enforcement import PolicyGuard
from mcp_warden.ratelimit import RateLimiter
from mcp_warden.upstreams import Upstream, UpstreamRegistry

FORWARDED_HEADERS: tuple[str, ...] = (SESSION_HEADER, PROTOCOL_HEADER)


@dataclass(frozen=True, slots=True)
class ProxyResult:
    """An HTTP-level answer: status, optional JSON body, extra headers."""

    status: int
    body: Any = None
    headers: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _Outcome:
    response: UpstreamResponse | JsonRpcErrorResponse | None = None
    session_id: str | None = None
    retry_after: int | None = None
    event: AuditEvent | None = None


def forwarded_headers(headers: Mapping[str, str]) -> dict[str, str]:
    lowered = {k.lower(): v for k, v in headers.items()}
    return {name: lowered[name] for name in FORWARDED_HEADERS if lowered.get(name)}


class ProxyService:
    def __init__(
        self,
        registry: UpstreamRegistry,
        transport: UpstreamTransport,
        guard: PolicyGuard,
        authenticator: Authenticator,
        limits: ParseLimits | None = None,
        limiter: RateLimiter | None = None,
        budgets: BudgetEnforcer | None = None,
        approvals: ApprovalGate | None = None,
        audit: AuditRecorder | None = None,
        *,
        tracer: Tracer | None = None,
        metrics: GatewayMetrics | None = None,
    ) -> None:
        # Events are built even without an audit store: metrics derive from them.
        self.audit = audit or AuditRecorder(None)
        self.tracer = tracer or tracer_from(None)
        self.metrics = metrics
        self.authenticator = authenticator
        self.approvals = approvals
        self.limiter = limiter
        self.budgets = budgets
        self.registry = registry
        self.transport = transport
        self.guard = guard
        self.limits = limits or ParseLimits()

    async def handle(self, server: str, body: bytes, headers: Mapping[str, str]) -> ProxyResult:
        try:
            agent = await self.authenticator.authenticate(headers)
        except AuthenticationError as exc:
            self._rejected("unauthenticated" if exc.status == 401 else "forbidden")
            return ProxyResult(exc.status, to_wire(error_response_from(exc, None)), exc.headers)

        upstream = self.registry.get(server)
        if upstream is None:
            self._rejected("unknown_server")
            err = error_response(
                None, ErrorCode.INVALID_REQUEST, "unknown server", {"server": server}
            )
            return ProxyResult(404, to_wire(err))

        forwarded = forwarded_headers(headers)
        limits = replace(self.limits, allow_batch=batching_allowed(forwarded.get(PROTOCOL_HEADER)))
        try:
            parsed = parse_payload(body, limits)
        except JsonRpcError as exc:
            too_large = exc.code == ErrorCode.PAYLOAD_TOO_LARGE
            self._rejected("payload_too_large" if too_large else "invalid_payload")
            return ProxyResult(413 if too_large else 400, to_wire(error_response_from(exc, None)))

        if not parsed.is_batch and isinstance(parsed.items[0], InvalidMessage):
            self._rejected("invalid_message")
            return ProxyResult(400, to_wire(parsed.items[0].error))

        parent = extract_context(headers)
        events: list[AuditEvent] = []
        try:
            outcomes = await asyncio.gather(
                *(
                    self._handle_item(agent, upstream, item, forwarded, events, parent)
                    for item in parsed.items
                )
            )
        except UpstreamSessionNotFoundError:
            # MCP: a 404 for a session id tells the client to re-initialise.
            return ProxyResult(404)
        finally:
            await self.audit.write(events)

        out_headers: dict[str, str] = {}
        session_id = next((o.session_id for o in outcomes if o.session_id), None)
        if session_id:
            out_headers[SESSION_HEADER] = session_id

        responses = [to_wire(o.response) for o in outcomes if o.response is not None]
        if not responses:
            return ProxyResult(202, None, out_headers)
        if not parsed.is_batch:
            # Only the gateway's own refusal sets it, never an upstream's error.
            retry_after = outcomes[0].retry_after
            if retry_after is not None:
                out_headers["Retry-After"] = str(retry_after)
        return ProxyResult(200, responses if parsed.is_batch else responses[0], out_headers)

    async def _handle_item(
        self,
        agent: str,
        upstream: Upstream,
        item: ParsedItem,
        forwarded: Mapping[str, str],
        events: list[AuditEvent],
        parent: otel_context.Context,
    ) -> _Outcome:
        if isinstance(item, InvalidMessage):
            return _Outcome(item.error)
        if isinstance(item, JsonRpcRequest):
            return await self._audited_request(agent, upstream, item, forwarded, events, parent)
        # Notifications and the agent's responses to server-initiated requests
        # have nobody to report a failure to, so failures end here.
        try:
            reply = await self.transport.send(
                upstream, to_wire(item), response_id=None, headers=forwarded
            )
        except JsonRpcError:
            return _Outcome()
        return _Outcome(None, reply.session_id)

    async def _audited_request(
        self,
        agent: str,
        upstream: Upstream,
        request: JsonRpcRequest,
        forwarded: Mapping[str, str],
        events: list[AuditEvent],
        parent: otel_context.Context,
    ) -> _Outcome:
        trace = self.audit.start(agent, upstream.name, request.method)
        attributes: dict[str, Any] = {
            ATTR_METHOD: request.method,
            ATTR_AGENT: agent,
            ATTR_SERVER: upstream.name,
        }
        if PROTOCOL_HEADER in forwarded:
            attributes[ATTR_PROTOCOL_VERSION] = forwarded[PROTOCOL_HEADER]
        with self.tracer.start_as_current_span(
            request.method,
            context=parent,
            kind=SpanKind.SERVER,
            attributes=attributes,
            record_exception=False,
            set_status_on_exception=False,
        ) as span:
            try:
                outcome = await self._forward_request(agent, upstream, request, forwarded, trace)
            except UpstreamSessionNotFoundError:
                event = self.audit.failed(trace, Outcome.UPSTREAM_ERROR)
                events.append(event)
                _annotate(span, event)
                raise
            event = outcome.event or self.audit.failed(trace, Outcome.ERROR)
            events.append(event)
            _annotate(span, event)
        return outcome

    @contextmanager
    def _stage(self, name: str) -> Iterator[None]:
        """A child span for a pipeline stage that can take time (locks, waits)."""
        with self.tracer.start_as_current_span(
            f"mcp_warden.{name}", record_exception=False, set_status_on_exception=False
        ):
            yield

    def _rejected(self, reason: str) -> None:
        if self.metrics is not None:
            self.metrics.rejected(reason)

    async def _forward_request(
        self,
        agent: str,
        upstream: Upstream,
        request: JsonRpcRequest,
        forwarded: Mapping[str, str],
        trace: Trace | None = None,
    ) -> _Outcome:
        reservation: Reservation | None = None
        try:
            if request.method == Method.TOOLS_CALL:
                # Validated first so malformed calls never reach the upstream and
                # the policy sees a well-formed tool name and arguments object.
                params = parse_call_tool(request)
                if trace is not None:
                    self.audit.note_arguments(trace, params.name, params.arguments)
                approval_id: str | None = None
                if self.approvals is None:
                    decision = self.guard.check_call(agent, upstream.name, params)
                else:
                    decision = self.guard.evaluate_call(agent, upstream.name, params)
                    if decision.effect is Effect.REQUIRE_APPROVAL:
                        with self._stage("approval"):
                            approval_id = await self.approvals.admit(
                                agent, upstream.name, params.name, params.arguments, decision
                            )
                if trace is not None:
                    trace.effect, trace.rule_id = decision.effect.value, decision.rule_id
                    trace.approval_id = approval_id
                if self.limiter is not None:
                    with self._stage("rate_limit"):
                        await self.limiter.check_call(agent, upstream.name, params.name)
                if self.budgets is not None:
                    with self._stage("budget"):
                        reservation = await self.budgets.reserve(
                            agent, upstream.name, params.name, params.arguments
                        )
                if self.approvals is not None and approval_id is not None:
                    # Spent last, so a call refused by a limit keeps its approval.
                    await self.approvals.claim(approval_id, upstream.name, params.name)
            reply = await self.transport.send(
                upstream, to_wire(request), response_id=request.id, headers=forwarded
            )
            response = reply.response
            if self.budgets is not None and reservation is not None and response is not None:
                await self.budgets.settle(reservation, response)
            if request.method == Method.TOOLS_LIST and isinstance(response, JsonRpcSuccess):
                response = self.guard.filter_tools(agent, upstream.name, response)
        except JsonRpcError as exc:
            retry_after = exc.retry_after if isinstance(exc, RetryAfterError) else None
            event = self._refused(trace, exc)
            return _Outcome(
                error_response_from(exc, request.id), retry_after=retry_after, event=event
            )
        event = None
        if trace is not None:
            event = self.audit.answered(trace, response)
        return _Outcome(response, reply.session_id, event=event)

    def _refused(self, trace: Trace | None, exc: JsonRpcError) -> AuditEvent | None:
        if trace is None:
            return None
        return self.audit.refused(trace, exc)


_ERROR_OUTCOMES = frozenset({Outcome.UPSTREAM_ERROR, Outcome.ERROR})


def _annotate(span: Span, event: AuditEvent) -> None:
    """Copy what the gateway decided onto the request's span (metadata only)."""
    span.set_attribute(ATTR_OUTCOME, event.outcome.value)
    if event.tool is not None:
        span.update_name(f"{event.method} {event.tool}")
        span.set_attribute(ATTR_TOOL, event.tool)
        span.set_attribute(ATTR_OPERATION, "execute_tool")
    if event.effect is not None:
        span.set_attribute(ATTR_EFFECT, event.effect)
    if event.rule_id is not None:
        span.set_attribute(ATTR_RULE, event.rule_id)
    if event.approval_id is not None:
        span.set_attribute(ATTR_APPROVAL, event.approval_id)
    if event.tool_error is not None:
        span.set_attribute(ATTR_TOOL_ERROR, event.tool_error)
    if event.error_code is not None:
        span.set_attribute(ATTR_JSONRPC_ERROR, event.error_code)
        span.set_attribute(ATTR_ERROR_TYPE, str(event.error_code))
    if event.outcome in _ERROR_OUTCOMES:
        # Refusals are the gateway working as intended; only failures are errors.
        span.set_status(Status(StatusCode.ERROR, event.outcome.value))
