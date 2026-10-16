"""The proxy pipeline for one ``POST /mcp/{server}`` call.

Responsibilities, in order:

1. authenticate the agent (see :mod:`mcp_warden.identity`); nothing else,
   not even whether a server exists, is revealed to an unauthenticated caller;
2. resolve the upstream by name (unknown servers never reach the network);
3. parse the payload with the hardened parser; batches are accepted only when
   the client declared an MCP revision that still allowed them;
4. handle each message: ``tools/call`` is checked against the policy and then
   the rate limits before it is forwarded (a denied call never spends a
   token), ``tools/list`` results are filtered on the way back, other
   requests are forwarded and answered, notifications and client responses
   are forwarded and acknowledged with ``202``;
5. map every refusal and upstream failure onto a JSON-RPC error carrying the
   request id. A single rate-limited call also gets a ``Retry-After`` header;
   the HTTP status stays ``200`` because MCP clients read the JSON-RPC error.

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
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any

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
    error_response,
    error_response_from,
    parse_payload,
    to_wire,
)
from mcp_warden.jsonrpc.mcp import Method, batching_allowed, parse_call_tool
from mcp_warden.proxy.client import (
    PROTOCOL_HEADER,
    SESSION_HEADER,
    UpstreamResponse,
    UpstreamSessionNotFoundError,
    UpstreamTransport,
)
from mcp_warden.proxy.enforcement import PolicyGuard
from mcp_warden.ratelimit import RateLimitedError, RateLimiter
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
    ) -> None:
        self.authenticator = authenticator
        self.limiter = limiter
        self.registry = registry
        self.transport = transport
        self.guard = guard
        self.limits = limits or ParseLimits()

    async def handle(self, server: str, body: bytes, headers: Mapping[str, str]) -> ProxyResult:
        try:
            agent = await self.authenticator.authenticate(headers)
        except AuthenticationError as exc:
            return ProxyResult(exc.status, to_wire(error_response_from(exc, None)), exc.headers)

        upstream = self.registry.get(server)
        if upstream is None:
            err = error_response(
                None, ErrorCode.INVALID_REQUEST, "unknown server", {"server": server}
            )
            return ProxyResult(404, to_wire(err))

        forwarded = forwarded_headers(headers)
        limits = replace(self.limits, allow_batch=batching_allowed(forwarded.get(PROTOCOL_HEADER)))
        try:
            parsed = parse_payload(body, limits)
        except JsonRpcError as exc:
            status = 413 if exc.code == ErrorCode.PAYLOAD_TOO_LARGE else 400
            return ProxyResult(status, to_wire(error_response_from(exc, None)))

        if not parsed.is_batch and isinstance(parsed.items[0], InvalidMessage):
            return ProxyResult(400, to_wire(parsed.items[0].error))

        try:
            outcomes = await asyncio.gather(
                *(self._handle_item(agent, upstream, item, forwarded) for item in parsed.items)
            )
        except UpstreamSessionNotFoundError:
            # MCP: a 404 for a session id tells the client to re-initialise.
            return ProxyResult(404)

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
        self, agent: str, upstream: Upstream, item: ParsedItem, forwarded: Mapping[str, str]
    ) -> _Outcome:
        if isinstance(item, InvalidMessage):
            return _Outcome(item.error)
        if isinstance(item, JsonRpcRequest):
            return await self._forward_request(agent, upstream, item, forwarded)
        # Notifications and the agent's responses to server-initiated requests
        # have nobody to report a failure to, so failures end here.
        try:
            reply = await self.transport.send(
                upstream, to_wire(item), response_id=None, headers=forwarded
            )
        except JsonRpcError:
            return _Outcome()
        return _Outcome(None, reply.session_id)

    async def _forward_request(
        self,
        agent: str,
        upstream: Upstream,
        request: JsonRpcRequest,
        forwarded: Mapping[str, str],
    ) -> _Outcome:
        try:
            if request.method == Method.TOOLS_CALL:
                # Validated first so malformed calls never reach the upstream and
                # the policy sees a well-formed tool name and arguments object.
                params = parse_call_tool(request)
                self.guard.check_call(agent, upstream.name, params)
                if self.limiter is not None:
                    await self.limiter.check_call(agent, upstream.name, params.name)
            reply = await self.transport.send(
                upstream, to_wire(request), response_id=request.id, headers=forwarded
            )
            response = reply.response
            if request.method == Method.TOOLS_LIST and isinstance(response, JsonRpcSuccess):
                response = self.guard.filter_tools(agent, upstream.name, response)
        except RateLimitedError as exc:
            return _Outcome(error_response_from(exc, request.id), retry_after=exc.retry_after)
        except JsonRpcError as exc:
            return _Outcome(error_response_from(exc, request.id))
        return _Outcome(response, reply.session_id)
