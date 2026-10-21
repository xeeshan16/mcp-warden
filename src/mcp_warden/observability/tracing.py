"""OpenTelemetry tracing.

The gateway code depends only on ``opentelemetry-api``. Without a configured
tracer provider every span is a no-op, so tracing costs next to nothing when
it is off. Exporting needs the SDK, installed with the ``otel`` extra
(``pip install 'mcp-warden[otel]'``):

* ``WARDEN_TRACING=console`` prints finished spans to stdout, for trying it out;
* ``WARDEN_TRACING=otlp`` sends them over OTLP/HTTP to
  ``WARDEN_OTLP_ENDPOINT`` (or the SDK's ``OTEL_EXPORTER_OTLP_*`` variables).

The provider is built per gateway and handed to the components that trace,
rather than installed as the process-global provider, so tests and embedding
applications keep control of global state.

Context propagation uses W3C Trace Context: a ``traceparent`` sent by the
agent becomes the parent of the gateway's spans, and the gateway sends its
own ``traceparent`` to the upstream, so one trace can cover agent, gateway
and MCP server. Spans never carry tool arguments, results, error messages or
MCP session ids (a session id is a capability for the upstream session).
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from enum import StrEnum

from opentelemetry import context as otel_context
from opentelemetry.trace import NoOpTracerProvider, Tracer, TracerProvider
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

from mcp_warden import __version__

TRACER_NAME = "mcp_warden"

_PROPAGATOR = TraceContextTextMapPropagator()

# Span attribute names. ``mcp.*`` and ``gen_ai.*`` follow the OpenTelemetry
# semantic conventions for MCP and generative AI; ``mcp_warden.*`` are the
# gateway's own.
ATTR_METHOD = "mcp.method.name"
ATTR_PROTOCOL_VERSION = "mcp.protocol.version"
ATTR_TOOL = "gen_ai.tool.name"
ATTR_OPERATION = "gen_ai.operation.name"
ATTR_ERROR_TYPE = "error.type"
ATTR_JSONRPC_ERROR = "rpc.jsonrpc.error_code"
ATTR_AGENT = "mcp_warden.agent"
ATTR_SERVER = "mcp_warden.server"
ATTR_OUTCOME = "mcp_warden.outcome"
ATTR_EFFECT = "mcp_warden.policy.effect"
ATTR_RULE = "mcp_warden.policy.rule_id"
ATTR_APPROVAL = "mcp_warden.approval.id"
ATTR_TOOL_ERROR = "mcp_warden.tool.is_error"


class TracingMode(StrEnum):
    OFF = "off"
    CONSOLE = "console"
    OTLP = "otlp"


class TracingUnavailableError(RuntimeError):
    """Tracing was requested but the OpenTelemetry SDK is not installed."""


def tracer_from(provider: TracerProvider | None) -> Tracer:
    return (provider or NoOpTracerProvider()).get_tracer(TRACER_NAME, __version__)


def extract_context(headers: Mapping[str, str]) -> otel_context.Context:
    """The trace context an agent sent in ``traceparent``/``tracestate``, if any."""
    lowered = {k.lower(): v for k, v in headers.items()}
    return _PROPAGATOR.extract(lowered)


def inject_context(headers: MutableMapping[str, str]) -> None:
    """Add the current span's ``traceparent`` (and ``tracestate``) to ``headers``."""
    _PROPAGATOR.inject(headers)


def build_tracer_provider(
    mode: TracingMode,
    *,
    service_name: str = "mcp-warden",
    otlp_endpoint: str | None = None,
    sample_ratio: float = 1.0,
) -> TracerProvider | None:
    """A configured SDK provider, or ``None`` when tracing is off.

    The caller owns the provider and should call ``shutdown()`` on it to flush
    spans when the gateway stops.
    """
    if mode is TracingMode.OFF:
        return None
    try:
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider as SdkTracerProvider
        from opentelemetry.sdk.trace.export import (
            BatchSpanProcessor,
            ConsoleSpanExporter,
            SpanExporter,
        )
        from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased
    except ImportError as exc:  # pragma: no cover - exercised without the extra
        raise TracingUnavailableError(
            "WARDEN_TRACING needs the OpenTelemetry SDK: pip install 'mcp-warden[otel]'"
        ) from exc
    provider = SdkTracerProvider(
        resource=Resource.create({"service.name": service_name, "service.version": __version__}),
        sampler=ParentBased(TraceIdRatioBased(sample_ratio)),
    )
    exporter: SpanExporter
    if mode is TracingMode.CONSOLE:
        exporter = ConsoleSpanExporter()
    else:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        except ImportError as exc:  # pragma: no cover - exercised without the extra
            raise TracingUnavailableError(
                "WARDEN_TRACING=otlp needs the OTLP exporter: pip install 'mcp-warden[otel]'"
            ) from exc
        exporter = OTLPSpanExporter(endpoint=otlp_endpoint) if otlp_endpoint else OTLPSpanExporter()
    provider.add_span_processor(BatchSpanProcessor(exporter))
    return provider


def shutdown_provider(provider: TracerProvider | None) -> None:
    shutdown = getattr(provider, "shutdown", None)
    if callable(shutdown):
        shutdown()
