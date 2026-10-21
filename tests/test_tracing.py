"""OpenTelemetry tracing: spans per request, propagation and what spans never hold."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any

import anyio
import httpx
import pytest
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind, StatusCode

from gateway_helpers import EXAMPLE_POLICY, initialize, make_client, rpc
from mcp_warden.jsonrpc import ErrorCode, success_response
from mcp_warden.observability.tracing import (
    TracingMode,
    build_tracer_provider,
    extract_context,
    shutdown_provider,
    tracer_from,
)
from mcp_warden.policy import PolicyEngine, load_policy_file
from mcp_warden.proxy import HttpUpstreamClient, InstrumentedTransport, UpstreamReply
from mcp_warden.upstreams import Upstream

TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
TRACEPARENT = f"00-{TRACE_ID}-00f067aa0ba902b7-01"
MARKER = "ticket-4711-do-not-log"


@pytest.fixture
def spans() -> Iterator[tuple[TracerProvider, InMemorySpanExporter]]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    yield provider, exporter
    provider.shutdown()


def by_name(exporter: InMemorySpanExporter) -> dict[str, ReadableSpan]:
    return {span.name: span for span in exporter.get_finished_spans()}


def everything_recorded(exporter: InMemorySpanExporter) -> str:
    """All names, attribute keys and values and status texts of every span."""
    parts: list[str] = []
    for span in exporter.get_finished_spans():
        parts.append(span.name)
        parts.append(span.status.description or "")
        for key, value in (span.attributes or {}).items():
            parts.extend([key, str(value)])
    return "\n".join(parts)


def test_a_tool_call_is_a_server_span_with_stage_and_upstream_children(
    spans: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    provider, exporter = spans
    engine = PolicyEngine(load_policy_file(EXAMPLE_POLICY))
    with make_client(engine=engine, tracer_provider=provider) as client:
        headers = {**initialize(client), "x-warden-agent": "support-bot"}
        exporter.clear()
        resp = client.post(
            "/mcp/demo",
            json=rpc(1, "tools/call", {"name": "add", "arguments": {"a": 1, "b": 2}}),
            headers={**headers, "traceparent": TRACEPARENT},
        )
        assert "result" in resp.json()

    found = by_name(exporter)
    server = found["tools/call add"]
    assert server.kind is SpanKind.SERVER
    # The agent's trace continues through the gateway.
    assert format(server.context.trace_id, "032x") == TRACE_ID
    assert server.parent is not None and server.parent.span_id == 0x00F067AA0BA902B7
    attrs = dict(server.attributes or {})
    assert attrs["mcp.method.name"] == "tools/call"
    assert attrs["gen_ai.tool.name"] == "add"
    assert attrs["gen_ai.operation.name"] == "execute_tool"
    assert attrs["mcp.protocol.version"] == "2025-11-25"
    assert attrs["mcp_warden.agent"] == "support-bot"
    assert attrs["mcp_warden.server"] == "demo"
    assert attrs["mcp_warden.outcome"] == "forwarded"
    assert attrs["mcp_warden.policy.effect"] == "allow"
    assert attrs["mcp_warden.policy.rule_id"] == "demo-basics"
    assert attrs["mcp_warden.tool.is_error"] is False
    assert server.status.status_code is StatusCode.UNSET

    upstream = found["POST demo"]
    assert upstream.kind is SpanKind.CLIENT
    assert upstream.parent is not None and upstream.parent.span_id == server.context.span_id
    up_attrs = dict(upstream.attributes or {})
    assert up_attrs["server.address"] == "upstream.test"
    assert up_attrs["http.response.status_code"] == 200
    for stage in ("mcp_warden.rate_limit", "mcp_warden.budget"):
        assert found[stage].parent is not None
        assert found[stage].parent.span_id == server.context.span_id


def test_refusals_are_annotated_but_not_errors_and_hold_no_arguments(
    spans: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    provider, exporter = spans
    engine = PolicyEngine(load_policy_file(EXAMPLE_POLICY))
    with make_client(engine=engine, tracer_provider=provider) as client:
        headers = {**initialize(client), "x-warden-agent": "support-bot"}
        exporter.clear()
        resp = client.post(
            "/mcp/demo",
            json=rpc(2, "tools/call", {"name": "delete_records", "arguments": {"id": MARKER}}),
            headers=headers,
        )
        assert resp.json()["error"]["code"] == ErrorCode.POLICY_DENIED

    span = by_name(exporter)["tools/call delete_records"]
    attrs = dict(span.attributes or {})
    assert attrs["mcp_warden.outcome"] == "denied"
    assert attrs["mcp_warden.policy.rule_id"] == "never-destructive"
    assert attrs["rpc.jsonrpc.error_code"] == ErrorCode.POLICY_DENIED
    assert attrs["error.type"] == str(int(ErrorCode.POLICY_DENIED))
    # The gateway refusing a call is it working, not failing.
    assert span.status.status_code is StatusCode.UNSET
    assert "POST demo" not in by_name(exporter)  # never reached the upstream
    recorded = everything_recorded(exporter)
    assert MARKER not in recorded
    # Session ids are capabilities for the upstream session; they stay out.
    assert headers["mcp-session-id"] not in recorded


def test_upstream_failures_mark_both_spans_as_errors(
    spans: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    provider, exporter = spans
    transport = HttpUpstreamClient(httpx.AsyncClient(transport=httpx.MockTransport(refuse)))
    with make_client(tracer_provider=provider, transport=transport) as client:
        client.post("/mcp/demo", json=rpc(1, "ping"), headers={"x-warden-agent": "bot"})

    found = by_name(exporter)
    assert found["ping"].status.status_code is StatusCode.ERROR
    assert dict(found["ping"].attributes or {})["mcp_warden.outcome"] == "upstream_error"
    upstream = found["POST demo"]
    assert upstream.status.status_code is StatusCode.ERROR
    assert dict(upstream.attributes or {})["error.type"] == "unreachable"


def test_batch_entries_are_sibling_spans(
    spans: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    provider, exporter = spans
    with make_client(tracer_provider=provider) as client:
        headers = {"x-warden-agent": "bot", "mcp-protocol-version": "2025-03-26"}
        batch = [
            rpc(1, "tools/call", {"name": "add", "arguments": {"a": 1, "b": 1}}),
            rpc(2, "tools/call", {"name": "echo", "arguments": {"text": "hi"}}),
        ]
        client.post("/mcp/demo", json=batch, headers={**headers, "traceparent": TRACEPARENT})

    found = by_name(exporter)
    add, echo = found["tools/call add"], found["tools/call echo"]
    assert add.context.span_id != echo.context.span_id
    assert add.parent is not None and echo.parent is not None
    assert add.parent.span_id == echo.parent.span_id == 0x00F067AA0BA902B7


class _Recording:
    def __init__(self) -> None:
        self.headers: list[Mapping[str, str]] = []

    async def send(
        self,
        upstream: Upstream,
        message: Mapping[str, Any],
        *,
        response_id: Any,
        headers: Mapping[str, str],
    ) -> UpstreamReply:
        self.headers.append(dict(headers))
        return UpstreamReply(200, success_response(response_id, {}))

    async def aclose(self) -> None:
        pass


def test_the_upstream_receives_the_gateways_traceparent(
    spans: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    provider, exporter = spans
    inner = _Recording()
    transport = InstrumentedTransport(inner, tracer=tracer_from(provider))
    upstream = Upstream("demo", "https://user:pw@mcp.example:8443/mcp?token=abc", 1.0, 1.0, {})

    anyio.run(
        lambda: transport.send(
            upstream, rpc(1, "ping"), response_id=1, headers={"mcp-protocol-version": "x"}
        )
    )
    sent = inner.headers[0]
    assert sent["mcp-protocol-version"] == "x"
    span = exporter.get_finished_spans()[0]
    trace_id, span_id = sent["traceparent"].split("-")[1:3]
    assert trace_id == format(span.context.trace_id, "032x")
    assert span_id == format(span.context.span_id, "016x")
    attrs = dict(span.attributes or {})
    assert (attrs["server.address"], attrs["server.port"]) == ("mcp.example", 8443)
    # Neither credentials nor query strings from the upstream URL are recorded.
    assert "pw" not in everything_recorded(exporter)
    assert "abc" not in everything_recorded(exporter)


def test_without_a_provider_tracing_is_a_no_op() -> None:
    inner = _Recording()
    transport = InstrumentedTransport(inner)
    upstream = Upstream("demo", "http://upstream.test/mcp", 1.0, 1.0, {})
    anyio.run(lambda: transport.send(upstream, rpc(1, "ping"), response_id=1, headers={}))
    assert "traceparent" not in inner.headers[0]


def test_malformed_incoming_trace_context_is_ignored() -> None:
    from opentelemetry import trace

    ctx = extract_context({"TraceParent": "00-not-a-trace-01"})
    assert not trace.get_current_span(ctx).get_span_context().is_valid
    ctx = extract_context({"TraceParent": TRACEPARENT})
    assert trace.get_current_span(ctx).get_span_context().is_valid


def test_building_providers_from_settings() -> None:
    assert build_tracer_provider(TracingMode.OFF) is None
    shutdown_provider(None)
    for mode in (TracingMode.CONSOLE, TracingMode.OTLP):
        provider = build_tracer_provider(
            mode,
            service_name="warden-test",
            otlp_endpoint="http://127.0.0.1:9/v1/traces",
            sample_ratio=0.5,
        )
        assert isinstance(provider, TracerProvider)
        assert provider.resource.attributes["service.name"] == "warden-test"
        shutdown_provider(provider)
