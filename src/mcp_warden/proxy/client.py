"""Forwarding JSON-RPC messages to upstream MCP servers over Streamable HTTP.

The upstream leg is the part of the gateway that talks to code it does not
control, so every failure mode is mapped onto a JSON-RPC error the agent can
act on:

* connect failures and non-JSON-RPC HTTP errors → ``UPSTREAM_ERROR``;
* exceeding the per-upstream deadline (including an SSE stream that keeps
  sending keep-alives but never answers) → ``UPSTREAM_TIMEOUT``;
* oversized, malformed or mismatched replies → ``UPSTREAM_ERROR``.

Upstream replies are parsed with the same hardened parser used for agent
input, and only the response whose id matches the forwarded request is
returned. Server-to-client messages interleaved on an SSE stream (progress
notifications, sampling requests) are counted and dropped for now; relaying
them is listed as follow-up work in the plan.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

import httpx

from mcp_warden.jsonrpc import (
    ErrorCode,
    InvalidMessage,
    JsonRpcError,
    JsonRpcErrorResponse,
    JsonRpcSuccess,
    ParseLimits,
    RequestId,
    decode_json,
    parse_object,
)
from mcp_warden.proxy.headers import SESSION_HEADER, valid_session_id
from mcp_warden.proxy.sse import iter_sse_events
from mcp_warden.upstreams import Upstream

ACCEPT = "application/json, text/event-stream"

UpstreamResponse = JsonRpcSuccess | JsonRpcErrorResponse


@dataclass(frozen=True, slots=True)
class UpstreamReply:
    """What came back for one forwarded message."""

    status: int
    response: UpstreamResponse | None
    session_id: str | None = None
    dropped_messages: int = 0


class UpstreamSessionNotFoundError(Exception):
    """The upstream answered 404 to a request carrying a session id.

    MCP clients react to that by starting a new session, so the gateway must
    pass the 404 through rather than turning it into a JSON-RPC error.
    """


class UpstreamTransport(Protocol):
    async def send(
        self,
        upstream: Upstream,
        message: Mapping[str, Any],
        *,
        response_id: RequestId | None,
        headers: Mapping[str, str],
    ) -> UpstreamReply: ...

    async def aclose(self) -> None: ...


def same_id(a: RequestId | None, b: RequestId | None) -> bool:
    """JSON-RPC id equality: ``1`` and ``"1"`` are different ids."""
    return type(a) is type(b) and a == b


class UpstreamFailureKind(StrEnum):
    """Why the upstream leg failed; a bounded label for metrics and traces."""

    UNREACHABLE = "unreachable"
    TIMEOUT = "timeout"
    HTTP_STATUS = "http_status"
    INVALID_RESPONSE = "invalid_response"
    TOO_LARGE = "too_large"
    REJECTED = "rejected"


class UpstreamFailureError(JsonRpcError):
    """A JSON-RPC error raised by the upstream leg, carrying why it failed.

    ``kind`` is for the gateway's own telemetry; it is not part of the error
    the agent sees, so it can be refined without changing the wire format.
    """

    def __init__(self, code: ErrorCode, message: str, data: Any, kind: UpstreamFailureKind) -> None:
        super().__init__(code, message, data)
        self.kind = kind


def _upstream_error(
    upstream: Upstream, message: str, kind: UpstreamFailureKind, **data: Any
) -> UpstreamFailureError:
    return UpstreamFailureError(
        ErrorCode.UPSTREAM_ERROR, message, {"server": upstream.name, **data}, kind
    )


class HttpUpstreamClient:
    """:class:`UpstreamTransport` backed by a shared ``httpx.AsyncClient``."""

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        *,
        max_response_bytes: int = 10_000_000,
        max_json_depth: int = 64,
    ) -> None:
        self._client = client or httpx.AsyncClient(follow_redirects=False)
        self._limits = ParseLimits(
            max_bytes=max_response_bytes, max_depth=max_json_depth, allow_batch=False
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def send(
        self,
        upstream: Upstream,
        message: Mapping[str, Any],
        *,
        response_id: RequestId | None,
        headers: Mapping[str, str],
    ) -> UpstreamReply:
        outgoing = {**upstream.headers, **headers, "accept": ACCEPT}
        outgoing["content-type"] = "application/json"
        body = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode()
        request = self._client.build_request(
            "POST",
            upstream.url,
            content=body,
            headers=outgoing,
            timeout=httpx.Timeout(
                upstream.timeout_seconds, connect=upstream.connect_timeout_seconds
            ),
        )
        sent_session = SESSION_HEADER in {k.lower() for k in headers}
        try:
            async with asyncio.timeout(upstream.timeout_seconds):
                resp = await self._client.send(request, stream=True)
                try:
                    return await self._read(upstream, resp, response_id, sent_session)
                finally:
                    await resp.aclose()
        except (TimeoutError, httpx.TimeoutException) as exc:
            raise UpstreamFailureError(
                ErrorCode.UPSTREAM_TIMEOUT,
                "upstream timed out",
                {"server": upstream.name, "timeout_seconds": upstream.timeout_seconds},
                UpstreamFailureKind.TIMEOUT,
            ) from exc
        except httpx.HTTPError as exc:
            raise _upstream_error(
                upstream, "upstream unreachable", UpstreamFailureKind.UNREACHABLE
            ) from exc

    async def _read(
        self,
        upstream: Upstream,
        resp: httpx.Response,
        response_id: RequestId | None,
        sent_session: bool,
    ) -> UpstreamReply:
        session_id = resp.headers.get(SESSION_HEADER)
        if resp.status_code == 404 and sent_session:
            raise UpstreamSessionNotFoundError(upstream.name)
        if session_id is not None and not valid_session_id(session_id):
            # Passed back to the agent and forwarded again: never relay junk.
            raise _upstream_error(
                upstream,
                "upstream sent an invalid session id",
                UpstreamFailureKind.INVALID_RESPONSE,
            )
        if response_id is None:
            # Notifications and responses: the server acknowledges with 202.
            if resp.status_code in (200, 202, 204):
                return UpstreamReply(resp.status_code, None, session_id)
            raise _upstream_error(
                upstream,
                "upstream rejected message",
                UpstreamFailureKind.REJECTED,
                status=resp.status_code,
            )

        content_type = resp.headers.get("content-type", "").split(";")[0].strip().lower()
        if content_type == "text/event-stream" and resp.status_code == 200:
            return await self._read_stream(upstream, resp, response_id, session_id)
        if content_type == "application/json":
            raw = await self._read_capped(upstream, resp.aiter_bytes())
            try:
                reply = self._to_response(upstream, self._decode(upstream, raw), response_id)
            except JsonRpcError:
                if resp.status_code >= 400:
                    raise _upstream_error(
                        upstream,
                        "upstream returned an HTTP error",
                        UpstreamFailureKind.HTTP_STATUS,
                        status=resp.status_code,
                    ) from None
                raise
            return UpstreamReply(resp.status_code, reply, session_id)
        if resp.status_code >= 400:
            raise _upstream_error(
                upstream,
                "upstream returned an HTTP error",
                UpstreamFailureKind.HTTP_STATUS,
                status=resp.status_code,
            )
        raise _upstream_error(
            upstream,
            "upstream returned an unsupported content type",
            UpstreamFailureKind.INVALID_RESPONSE,
            content_type=content_type,
        )

    async def _read_capped(self, upstream: Upstream, chunks: AsyncIterator[bytes]) -> bytes:
        buf = bytearray()
        async for chunk in chunks:
            buf.extend(chunk)
            if len(buf) > self._limits.max_bytes:
                raise _upstream_error(
                    upstream,
                    "upstream response too large",
                    UpstreamFailureKind.TOO_LARGE,
                    max_bytes=self._limits.max_bytes,
                )
        return bytes(buf)

    async def _read_stream(
        self,
        upstream: Upstream,
        resp: httpx.Response,
        response_id: RequestId,
        session_id: str | None,
    ) -> UpstreamReply:
        total = 0
        limit = self._limits.max_bytes

        async def capped_lines() -> AsyncIterator[str]:
            nonlocal total
            async for line in resp.aiter_lines():
                total += len(line) + 1
                if total > limit:
                    raise _upstream_error(
                        upstream,
                        "upstream response too large",
                        UpstreamFailureKind.TOO_LARGE,
                        max_bytes=limit,
                    )
                yield line

        dropped = 0
        async for event in iter_sse_events(capped_lines()):
            if event.event != "message" or not event.data.strip():
                continue
            value = self._decode(upstream, event.data)
            if (
                isinstance(value, dict)
                and ("result" in value or "error" in value)
                and same_id(value.get("id"), response_id)
            ):
                reply = self._to_response(upstream, value, response_id)
                return UpstreamReply(resp.status_code, reply, session_id, dropped)
            dropped += 1
        raise _upstream_error(
            upstream,
            "upstream closed the stream without a response",
            UpstreamFailureKind.INVALID_RESPONSE,
        )

    def _decode(self, upstream: Upstream, raw: bytes | str) -> Any:
        # Re-label parse failures: a PARSE_ERROR would tell the agent that *its*
        # payload was malformed.
        try:
            return decode_json(raw, self._limits)
        except JsonRpcError as exc:
            raise _upstream_error(
                upstream,
                "upstream sent invalid JSON",
                UpstreamFailureKind.INVALID_RESPONSE,
                reason=exc.message,
            ) from exc

    @staticmethod
    def _to_response(upstream: Upstream, value: Any, response_id: RequestId) -> UpstreamResponse:
        parsed = parse_object(value)
        if isinstance(parsed, InvalidMessage) or not isinstance(
            parsed, JsonRpcSuccess | JsonRpcErrorResponse
        ):
            raise _upstream_error(
                upstream,
                "upstream sent an invalid JSON-RPC response",
                UpstreamFailureKind.INVALID_RESPONSE,
            )
        if not same_id(parsed.id, response_id):
            raise _upstream_error(
                upstream,
                "upstream response id does not match the request",
                UpstreamFailureKind.INVALID_RESPONSE,
            )
        return parsed
