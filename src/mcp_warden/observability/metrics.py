"""Prometheus metrics for the gateway.

Most metrics are derived from the same request events the audit log is built
from (see :class:`mcp_warden.audit.AuditRecorder`), so a metric and the audit
trail can never disagree about what happened to a call. The rest come from
three narrow hooks: the upstream transport (latency and failure kind of the
upstream leg), the budget enforcer (what was booked and refused) and the
HTTP layer (requests rejected before any JSON-RPC handling, and every route's
status codes).

State that already lives somewhere (policy in force, reload counters, audit
write failures) is read at scrape time by :class:`StateCollector` instead of
being mirrored into gauges that could drift.

Every metric lives in the registry of one :class:`GatewayMetrics`, never in
the process-global default registry, so several gateways (or tests) in one
process do not see each other's numbers.

Labels never carry arguments, results or error messages, and every label
fed by agent-controlled input is bounded (see :mod:`.labels`).
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import TYPE_CHECKING

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
)
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily, Metric
from prometheus_client.registry import Collector

from mcp_warden import __version__
from mcp_warden.audit.model import AuditEvent
from mcp_warden.budget.ledger import Charge, Refusal
from mcp_warden.observability.labels import LabelGuard, method_label

if TYPE_CHECKING:
    from mcp_warden.audit.recorder import AuditRecorder
    from mcp_warden.policy.reload import PolicyReloader

CONTENT_TYPE = CONTENT_TYPE_LATEST

# Request latency through the gateway: sub-millisecond refusals up to calls
# held for a human decision (``WARDEN_APPROVAL_WAIT_SECONDS`` caps at 60 s).
REQUEST_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60)
UPSTREAM_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60)

SESSION_LOST = "session_lost"
OK = "ok"


class GatewayMetrics:
    def __init__(self, *, max_label_values: int = 1000) -> None:
        self.registry = CollectorRegistry(auto_describe=True)
        r = self.registry
        self.label_overflow = Counter(
            "mcp_warden_metric_label_overflow",
            "Label values reported as __other__ because the label hit its value limit.",
            ["label"],
            registry=r,
        )
        self._guard = LabelGuard(
            max_label_values, lambda label: self.label_overflow.labels(label=label).inc()
        )
        self.requests = Counter(
            "mcp_warden_requests",
            "JSON-RPC requests handled, by upstream, method and outcome.",
            ["server", "method", "outcome"],
            registry=r,
        )
        self.request_duration = Histogram(
            "mcp_warden_request_duration_seconds",
            "Time from receiving a JSON-RPC request to answering it.",
            ["server", "method", "outcome"],
            buckets=REQUEST_BUCKETS,
            registry=r,
        )
        self.tool_calls = Counter(
            "mcp_warden_tool_calls",
            "tools/call requests, by agent, upstream, tool and outcome.",
            ["agent", "server", "tool", "outcome"],
            registry=r,
        )
        self.tool_errors = Counter(
            "mcp_warden_tool_errors",
            "Forwarded tools/call requests whose result had isError set.",
            ["server", "tool"],
            registry=r,
        )
        self.policy_decisions = Counter(
            "mcp_warden_policy_decisions",
            "Policy decisions on tools/call, by agent, upstream, effect and deciding rule.",
            ["agent", "server", "effect", "rule"],
            registry=r,
        )
        self.upstream_requests = Counter(
            "mcp_warden_upstream_requests",
            "Messages sent to upstream servers, by result (ok or the failure kind).",
            ["server", "result"],
            registry=r,
        )
        self.upstream_duration = Histogram(
            "mcp_warden_upstream_duration_seconds",
            "Time spent waiting for an upstream server, failures included.",
            ["server"],
            buckets=UPSTREAM_BUCKETS,
            registry=r,
        )
        self.rejections = Counter(
            "mcp_warden_http_rejections",
            "MCP HTTP requests refused before any message was handled, by reason.",
            ["reason"],
            registry=r,
        )
        self.budget_calls = Counter(
            "mcp_warden_budget_calls",
            "Calls booked against budgets, by budget and agent.",
            ["budget", "agent"],
            registry=r,
        )
        self.budget_tokens = Counter(
            "mcp_warden_budget_tokens",
            "Estimated tokens booked against budgets (requests and replies).",
            ["budget", "agent"],
            registry=r,
        )
        self.budget_refusals = Counter(
            "mcp_warden_budget_refusals",
            "Calls refused because a budget was exhausted, by budget, agent and limit hit.",
            ["budget", "agent", "exhausted"],
            registry=r,
        )
        self.http_requests = Counter(
            "mcp_warden_http_requests",
            "HTTP requests by route template, method and status code.",
            ["route", "method", "status"],
            registry=r,
        )
        self.http_duration = Histogram(
            "mcp_warden_http_request_duration_seconds",
            "HTTP request duration by route template and method.",
            ["route", "method"],
            buckets=REQUEST_BUCKETS,
            registry=r,
        )

    # -- request events -------------------------------------------------

    def observe_events(self, events: Sequence[AuditEvent]) -> None:
        """An :data:`~mcp_warden.audit.recorder.EventObserver` for the recorder."""
        for event in events:
            self._observe(event)

    def _observe(self, event: AuditEvent) -> None:
        method = method_label(event.method)
        outcome = event.outcome.value
        self.requests.labels(event.server, method, outcome).inc()
        self.request_duration.labels(event.server, method, outcome).observe(event.latency_ms / 1000)
        if event.method != "tools/call":
            return
        agent = self._guard("agent", event.agent)
        tool = self._guard("tool", event.tool)
        self.tool_calls.labels(agent, event.server, tool, outcome).inc()
        if event.tool_error:
            self.tool_errors.labels(event.server, tool).inc()
        if event.effect is not None:
            rule = self._guard("rule", event.rule_id) if event.rule_id else "default"
            self.policy_decisions.labels(agent, event.server, event.effect, rule).inc()

    # -- upstream leg ---------------------------------------------------

    def observe_upstream(self, server: str, seconds: float, result: str) -> None:
        self.upstream_requests.labels(server, result).inc()
        self.upstream_duration.labels(server).observe(seconds)

    # -- HTTP layer -----------------------------------------------------

    def rejected(self, reason: str) -> None:
        self.rejections.labels(reason).inc()

    def observe_http(self, route: str, method: str, status: int, seconds: float) -> None:
        self.http_requests.labels(route, method, str(status)).inc()
        self.http_duration.labels(route, method).observe(seconds)

    # -- budgets (a BudgetObserver) ---------------------------------------

    def booked(self, charges: Sequence[Charge], calls: int, tokens: int) -> None:
        for charge in charges:
            agent = self._guard("agent", charge.agent)
            if calls:
                self.budget_calls.labels(charge.budget.id, agent).inc(calls)
            if tokens:
                self.budget_tokens.labels(charge.budget.id, agent).inc(tokens)

    def refused(self, refusal: Refusal) -> None:
        charge = refusal.charge
        agent = self._guard("agent", charge.agent)
        self.budget_refusals.labels(charge.budget.id, agent, refusal.exhausted.value).inc()

    # -- state and exposition --------------------------------------------

    def track_state(
        self, reloader: PolicyReloader | None = None, recorder: AuditRecorder | None = None
    ) -> None:
        self.registry.register(StateCollector(reloader, recorder))

    def exposition(self) -> bytes:
        return generate_latest(self.registry)


class StateCollector(Collector):
    """Reads the gateway's own state at scrape time."""

    def __init__(self, reloader: PolicyReloader | None, recorder: AuditRecorder | None) -> None:
        self.reloader = reloader
        self.recorder = recorder

    def collect(self) -> Iterator[Metric]:
        info = GaugeMetricFamily(
            "mcp_warden_build_info", "Always 1; the gateway version.", labels=["version"]
        )
        info.add_metric([__version__], 1)
        yield info
        if self.reloader is not None:
            yield from self._policy(self.reloader)
        if self.recorder is not None:
            failures = CounterMetricFamily(
                "mcp_warden_audit_write_failures",
                "Batches of audit events that could not be stored (the calls still went on).",
            )
            failures.add_metric([], self.recorder.failed_writes)
            yield failures
            written = CounterMetricFamily("mcp_warden_audit_events_written", "Audit events stored.")
            written.add_metric([], self.recorder.written_events)
            yield written

    @staticmethod
    def _policy(reloader: PolicyReloader) -> Iterator[Metric]:
        policy = reloader.engine.policy
        info = GaugeMetricFamily(
            "mcp_warden_policy_info",
            "Always 1; the policy in force (schema version and first 12 hex of its SHA-256).",
            labels=["version", "sha256"],
        )
        info.add_metric([str(policy.version), (reloader.sha256 or "")[:12]], 1)
        yield info
        rules = GaugeMetricFamily("mcp_warden_policy_rules", "Rules in the policy in force.")
        rules.add_metric([], len(policy.rules))
        yield rules
        reloads = CounterMetricFamily(
            "mcp_warden_policy_reloads", "Reloads that swapped in a changed policy."
        )
        reloads.add_metric([], reloader.reloads)
        yield reloads
        failed = CounterMetricFamily(
            "mcp_warden_policy_reload_failures",
            "Reload attempts refused because the file was unreadable or invalid.",
        )
        failed.add_metric([], reloader.failed_reloads)
        yield failed
        error = GaugeMetricFamily(
            "mcp_warden_policy_reload_error",
            "1 while the latest reload attempt failed and an older policy is in force.",
        )
        error.add_metric([], 1 if reloader.last_error is not None else 0)
        yield error
        if reloader.loaded_at is not None:
            loaded = GaugeMetricFamily(
                "mcp_warden_policy_loaded_timestamp_seconds",
                "When the policy in force was loaded (Unix time).",
            )
            loaded.add_metric([], reloader.loaded_at.timestamp())
            yield loaded
