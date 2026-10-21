"""Metrics and tracing for the upstream leg, as a wrapper around any transport.

Kept out of :class:`~mcp_warden.proxy.client.HttpUpstreamClient` so the
transport stays about HTTP and MCP, and so tests can instrument a fake
transport the same way.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlsplit

from opentelemetry.trace import SpanKind, Status, StatusCode, Tracer

from mcp_warden.jsonrpc import JsonRpcError, RequestId
from mcp_warden.observability.metrics import OK, SESSION_LOST, GatewayMetrics
from mcp_warden.observability.tracing import (
    ATTR_ERROR_TYPE,
    ATTR_METHOD,
    ATTR_SERVER,
    inject_context,
    tracer_from,
)
from mcp_warden.proxy.client import (
    UpstreamFailureError,
    UpstreamReply,
    UpstreamSessionNotFoundError,
    UpstreamTransport,
)
from mcp_warden.upstreams import Upstream


def failure_kind(exc: BaseException) -> str:
    if isinstance(exc, UpstreamSessionNotFoundError):
        return SESSION_LOST
    if isinstance(exc, UpstreamFailureError):
        return exc.kind.value
    return "error"


class InstrumentedTransport:
    """An :class:`UpstreamTransport` that times, counts and traces every send."""

    def __init__(
        self,
        inner: UpstreamTransport,
        *,
        metrics: GatewayMetrics | None = None,
        tracer: Tracer | None = None,
        timer: Callable[[], float] = time.perf_counter,
    ) -> None:
        self.inner = inner
        self.metrics = metrics
        self.tracer = tracer or tracer_from(None)
        self._timer = timer

    async def aclose(self) -> None:
        await self.inner.aclose()

    async def send(
        self,
        upstream: Upstream,
        message: Mapping[str, Any],
        *,
        response_id: RequestId | None,
        headers: Mapping[str, str],
    ) -> UpstreamReply:
        url = urlsplit(upstream.url)
        attributes: dict[str, Any] = {
            ATTR_SERVER: upstream.name,
            "http.request.method": "POST",
            # Host and port only: upstream URLs may carry credentials or tokens.
            "server.address": url.hostname or "",
        }
        if url.port is not None:
            attributes["server.port"] = url.port
        method = message.get("method")
        if isinstance(method, str):
            attributes[ATTR_METHOD] = method
        started = self._timer()
        with self.tracer.start_as_current_span(
            f"POST {upstream.name}",
            kind=SpanKind.CLIENT,
            attributes=attributes,
            record_exception=False,
            set_status_on_exception=False,
        ) as span:
            outgoing = dict(headers)
            inject_context(outgoing)
            try:
                reply = await self.inner.send(
                    upstream, message, response_id=response_id, headers=outgoing
                )
            except (JsonRpcError, UpstreamSessionNotFoundError) as exc:
                kind = failure_kind(exc)
                span.set_attribute(ATTR_ERROR_TYPE, kind)
                span.set_status(Status(StatusCode.ERROR, kind))
                self._observe(upstream, started, kind)
                raise
            span.set_attribute("http.response.status_code", reply.status)
            self._observe(upstream, started, OK)
            return reply

    def _observe(self, upstream: Upstream, started: float, result: str) -> None:
        if self.metrics is not None:
            self.metrics.observe_upstream(upstream.name, self._timer() - started, result)
