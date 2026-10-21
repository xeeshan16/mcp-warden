"""Prometheus metrics: label bounds, derivation from events, state and the endpoint."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from conftest import FakeClock, FakeMonotonic
from gateway_helpers import EXAMPLE_POLICY, initialize, make_client, rpc
from mcp_warden.audit import AuditEvent, AuditRecorder, InMemoryAuditStore, Outcome
from mcp_warden.budget import BudgetEnforcer, CharRatioEstimator, InMemoryUsageStore
from mcp_warden.jsonrpc import ErrorCode, JsonRpcError
from mcp_warden.observability.labels import OVERFLOW, LabelGuard, method_label
from mcp_warden.observability.metrics import GatewayMetrics, StateCollector
from mcp_warden.policy import PolicyEngine, PolicyReloader, load_policy_file, parse_policy
from mcp_warden.proxy import HttpUpstreamClient
from mcp_warden.ratelimit import InMemoryBucketStore

METRICS_TOKEN = "metrics-token-for-tests"  # noqa: S105 - test fixture, not a secret
NOW = datetime(2026, 10, 21, 9, 0, tzinfo=UTC)


def sample(metrics: GatewayMetrics, name: str, **labels: str) -> float:
    value = metrics.registry.get_sample_value(name, labels)
    return 0.0 if value is None else value


def event(**overrides: Any) -> AuditEvent:
    fields: dict[str, Any] = {
        "occurred_at": NOW,
        "agent": "support-bot",
        "server": "demo",
        "method": "tools/call",
        "outcome": Outcome.FORWARDED,
        "latency_ms": 12.0,
        "tool": "add",
        "effect": "allow",
        "rule_id": "demo-basics",
    }
    fields.update(overrides)
    return AuditEvent.create(**fields)


def call(client: TestClient, headers: dict[str, str], tool: str, **args: Any) -> dict[str, Any]:
    resp = client.post(
        "/mcp/demo", json=rpc(1, "tools/call", {"name": tool, "arguments": args}), headers=headers
    )
    assert resp.status_code == 200
    body: dict[str, Any] = resp.json()
    return body


# -- labels ---------------------------------------------------------------


def test_label_guard_admits_a_bounded_number_of_values_per_label() -> None:
    overflowed: list[str] = []
    guard = LabelGuard(2, overflowed.append)
    assert [guard("tool", t) for t in ("a", "b", "a", "c", "d")] == [
        "a",
        "b",
        "a",
        OVERFLOW,
        OVERFLOW,
    ]
    # Limits are per label name.
    assert guard("agent", "c") == "c"
    assert guard("tool", None) == ""
    assert overflowed == ["tool", "tool"]
    assert guard.size("tool") == 2
    with pytest.raises(ValueError, match="at least 1"):
        LabelGuard(0)


def test_unknown_methods_share_one_label() -> None:
    assert method_label("tools/call") == "tools/call"
    assert method_label("resources/read") == "resources/read"
    assert method_label("x/" + "a" * 500) == "other"


# -- derived from request events -------------------------------------------


def test_events_feed_request_tool_call_and_decision_metrics() -> None:
    metrics = GatewayMetrics()
    metrics.observe_events(
        [
            event(),
            event(tool_error=True, latency_ms=40.0),
            event(outcome=Outcome.DENIED, tool="delete_records", effect="deny", rule_id="nope"),
            event(method="tools/list", tool=None, effect=None, rule_id=None),
            event(method="vendor/thing", tool=None, effect=None, rule_id=None),
            event(outcome=Outcome.RATE_LIMITED, rule_id=None),
        ]
    )
    m = metrics
    assert (
        sample(
            m, "mcp_warden_requests_total", server="demo", method="tools/call", outcome="forwarded"
        )
        == 2
    )
    assert (
        sample(m, "mcp_warden_requests_total", server="demo", method="other", outcome="forwarded")
        == 1
    )
    assert sample(
        m,
        "mcp_warden_request_duration_seconds_sum",
        server="demo",
        method="tools/call",
        outcome="forwarded",
    ) == pytest.approx(0.052)
    assert (
        sample(
            m,
            "mcp_warden_tool_calls_total",
            agent="support-bot",
            server="demo",
            tool="delete_records",
            outcome="denied",
        )
        == 1
    )
    assert sample(m, "mcp_warden_tool_errors_total", server="demo", tool="add") == 1
    assert (
        sample(
            m,
            "mcp_warden_policy_decisions_total",
            agent="support-bot",
            server="demo",
            effect="deny",
            rule="nope",
        )
        == 1
    )
    # A decision made by the policy default has no rule id.
    assert (
        sample(
            m,
            "mcp_warden_policy_decisions_total",
            agent="support-bot",
            server="demo",
            effect="allow",
            rule="default",
        )
        == 1
    )
    # tools/list is a request but not a tool call.
    assert (
        sample(
            m,
            "mcp_warden_tool_calls_total",
            agent="support-bot",
            server="demo",
            tool="",
            outcome="forwarded",
        )
        == 0
    )


def test_tool_names_from_agents_cannot_grow_series_without_bound() -> None:
    metrics = GatewayMetrics(max_label_values=3)
    metrics.observe_events(
        [event(tool=f"made_up_{i}", outcome=Outcome.DENIED, effect="deny") for i in range(50)]
    )
    exposition = metrics.exposition().decode()
    # Three admitted tools, each a tool_calls series with a _total and a _created sample.
    assert exposition.count("made_up_") == 3 * 2
    assert (
        sample(
            metrics,
            "mcp_warden_tool_calls_total",
            agent="support-bot",
            server="demo",
            tool=OVERFLOW,
            outcome="denied",
        )
        == 47
    )
    assert sample(metrics, "mcp_warden_metric_label_overflow_total", label="tool") == 47


def test_budget_observer_counts_bookings_and_refusals() -> None:
    policy = parse_policy(
        {
            "version": 1,
            "default": "allow",
            "budgets": [{"id": "two-calls", "window": "hour", "max_calls": 2}],
        }
    )
    metrics = GatewayMetrics()
    enforcer = BudgetEnforcer(
        PolicyEngine(policy),
        InMemoryUsageStore(clock=lambda: NOW),
        CharRatioEstimator(4.0),
        lambda: NOW,
        observer=metrics,
    )

    async def run() -> None:
        from mcp_warden.jsonrpc import success_response

        reservation = await enforcer.reserve("bot", "demo", "add", {"a": 1})
        assert reservation is not None
        await enforcer.settle(reservation, success_response(1, {"content": [{"text": "x" * 40}]}))
        await enforcer.reserve("bot", "demo", "add", {"a": 2})
        with pytest.raises(Exception, match="budget exhausted"):
            await enforcer.reserve("bot", "demo", "add", {"a": 3})

    import anyio

    anyio.run(run)
    assert sample(metrics, "mcp_warden_budget_calls_total", budget="two-calls", agent="bot") == 2
    tokens = sample(metrics, "mcp_warden_budget_tokens_total", budget="two-calls", agent="bot")
    assert tokens > 10  # request tokens of two calls plus the reply's
    assert (
        sample(
            metrics,
            "mcp_warden_budget_refusals_total",
            budget="two-calls",
            agent="bot",
            exhausted="calls",
        )
        == 1
    )


def test_a_failing_budget_observer_never_fails_the_call() -> None:
    class Broken:
        def booked(self, *args: Any) -> None:
            raise RuntimeError("boom")

        def refused(self, *args: Any) -> None:
            raise RuntimeError("boom")

    policy = parse_policy(
        {
            "version": 1,
            "default": "allow",
            "budgets": [{"id": "b", "window": "hour", "max_calls": 9}],
        }
    )
    enforcer = BudgetEnforcer(
        PolicyEngine(policy),
        InMemoryUsageStore(clock=lambda: NOW),
        CharRatioEstimator(4.0),
        lambda: NOW,
        observer=Broken(),
    )
    import anyio

    assert anyio.run(enforcer.reserve, "bot", "demo", "add", {}) is not None


# -- state read at scrape time -----------------------------------------------


def test_state_collector_reports_policy_reloads_and_audit_writes(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(EXAMPLE_POLICY.read_text())
    reloader = PolicyReloader.from_file(policy_file, clock=FakeClock(NOW))
    recorder = AuditRecorder(InMemoryAuditStore(10))
    metrics = GatewayMetrics()
    metrics.track_state(reloader, recorder)

    rules = len(load_policy_file(EXAMPLE_POLICY).rules)
    assert sample(metrics, "mcp_warden_policy_rules") == rules
    assert (
        sample(metrics, "mcp_warden_policy_info", version="1", sha256=(reloader.sha256 or "")[:12])
        == 1
    )
    assert sample(metrics, "mcp_warden_policy_loaded_timestamp_seconds") == NOW.timestamp()
    assert sample(metrics, "mcp_warden_policy_reload_error") == 0

    policy_file.write_text("version: 1\ndefault: maybe\n")
    assert reloader.check() is None
    assert sample(metrics, "mcp_warden_policy_reload_failures_total") == 1
    assert sample(metrics, "mcp_warden_policy_reload_error") == 1

    policy_file.write_text("version: 1\ndefault: deny\n")
    assert reloader.check() is not None
    assert sample(metrics, "mcp_warden_policy_reloads_total") == 1
    assert sample(metrics, "mcp_warden_policy_reload_error") == 0
    assert sample(metrics, "mcp_warden_policy_rules") == 0

    import anyio

    anyio.run(recorder.write, [event(), event()])
    assert sample(metrics, "mcp_warden_audit_events_written_total") == 2
    assert sample(metrics, "mcp_warden_audit_write_failures_total") == 0


def test_state_collector_without_sources_still_reports_the_build() -> None:
    families = list(StateCollector(None, None).collect())
    assert [f.name for f in families] == ["mcp_warden_build_info"]


def test_recorder_feeds_observers_even_without_a_store_and_survives_a_broken_one() -> None:
    seen: list[int] = []

    def broken(events: Any) -> None:
        raise RuntimeError("boom")

    recorder = AuditRecorder(None, observers=[broken, lambda events: seen.append(len(events))])
    trace = recorder.start("bot", "demo", "tools/call")
    recorder.note_arguments(trace, "add", {"a": 1})
    assert trace.arguments_digest is None  # nothing would keep it

    import anyio

    anyio.run(recorder.write, [recorder.failed(trace, Outcome.ERROR)])
    assert seen == [1]
    assert recorder.written_events == 0


# -- through the gateway -------------------------------------------------------


def scrape(client: TestClient, **headers: str) -> str:
    resp = client.get("/metrics", headers=headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    return resp.text


def test_gateway_exports_metrics_for_proxied_traffic() -> None:
    metrics = GatewayMetrics()
    engine = PolicyEngine(load_policy_file(EXAMPLE_POLICY))
    with make_client(engine=engine, metrics=metrics) as client:
        headers = {**initialize(client), "x-warden-agent": "support-bot"}
        assert "result" in call(client, headers, "add", a=1, b=2)
        assert call(client, headers, "delete_records", table="t")["error"]["code"] == (
            ErrorCode.POLICY_DENIED
        )
        assert client.post("/mcp/nowhere", json=rpc(1, "ping"), headers=headers).status_code == 404
        assert (
            client.post(
                "/mcp/demo", content=b"{", headers={**headers, "content-type": "application/json"}
            ).status_code
            == 400
        )
        assert (
            client.post(
                "/mcp/demo", content=b"x", headers={**headers, "content-type": "text/plain"}
            ).status_code
            == 415
        )
        text = scrape(client)

    m = metrics
    assert (
        sample(
            m,
            "mcp_warden_tool_calls_total",
            agent="support-bot",
            server="demo",
            tool="add",
            outcome="forwarded",
        )
        == 1
    )
    assert (
        sample(
            m,
            "mcp_warden_policy_decisions_total",
            agent="support-bot",
            server="demo",
            effect="deny",
            rule="never-destructive",
        )
        == 1
    )
    assert (
        sample(
            m, "mcp_warden_requests_total", server="demo", method="initialize", outcome="forwarded"
        )
        == 1
    )
    # initialize and the allowed call reached the upstream; the denied call did not.
    assert sample(m, "mcp_warden_upstream_requests_total", server="demo", result="ok") == 2
    assert sample(m, "mcp_warden_upstream_duration_seconds_count", server="demo") == 2
    for reason in ("unknown_server", "invalid_payload", "unsupported_media_type"):
        assert sample(m, "mcp_warden_http_rejections_total", reason=reason) == 1
    # Route templates, never raw paths, become labels. A policy refusal is a
    # JSON-RPC error in a 200 response: initialize, add and delete_records.
    ok = {"route": "/mcp/{server}", "method": "POST", "status": "200"}
    assert sample(m, "mcp_warden_http_requests_total", **ok) == 3
    assert sample(m, "mcp_warden_http_requests_total", **{**ok, "status": "404"}) == 1
    assert "/mcp/nowhere" not in text
    assert 'mcp_warden_build_info{version="' in text
    assert "mcp_warden_policy_rules" in text
    # Arguments never become labels.
    assert "table" not in text


def test_upstream_failures_are_counted_by_kind() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    metrics = GatewayMetrics()
    transport = HttpUpstreamClient(httpx.AsyncClient(transport=httpx.MockTransport(refuse)))
    with make_client(metrics=metrics, transport=transport) as client:
        resp = client.post("/mcp/demo", json=rpc(1, "ping"), headers={"x-warden-agent": "a"})
        assert resp.json()["error"]["code"] == ErrorCode.UPSTREAM_ERROR
        # The kind is for telemetry only; the agent sees the same error as before.
        assert resp.json()["error"]["data"] == {"server": "demo"}
    assert (
        sample(metrics, "mcp_warden_upstream_requests_total", server="demo", result="unreachable")
        == 1
    )
    assert (
        sample(
            metrics,
            "mcp_warden_requests_total",
            server="demo",
            method="ping",
            outcome="upstream_error",
        )
        == 1
    )


def test_metrics_follow_requests_with_the_audit_log_off() -> None:
    metrics = GatewayMetrics()
    with make_client(metrics=metrics, audit_store="off") as client:
        headers = {**initialize(client), "x-warden-agent": "bot"}
        call(client, headers, "add", a=1, b=2)
    assert (
        sample(
            metrics,
            "mcp_warden_tool_calls_total",
            agent="bot",
            server="demo",
            tool="add",
            outcome="forwarded",
        )
        == 1
    )


def test_rate_limited_calls_are_counted() -> None:
    policy = parse_policy(
        {
            "version": 1,
            "default": "allow",
            "rate_limits": [{"id": "one", "tools": ["add"], "requests": 1, "per": "hour"}],
        }
    )
    metrics = GatewayMetrics()
    with make_client(
        engine=PolicyEngine(policy),
        bucket_store=InMemoryBucketStore(clock=FakeMonotonic()),
        metrics=metrics,
    ) as client:
        headers = {**initialize(client), "x-warden-agent": "bot"}
        call(client, headers, "add", a=1, b=2)
        assert call(client, headers, "add", a=1, b=2)["error"]["code"] == ErrorCode.RATE_LIMITED
    assert (
        sample(
            metrics,
            "mcp_warden_tool_calls_total",
            agent="bot",
            server="demo",
            tool="add",
            outcome="rate_limited",
        )
        == 1
    )


def test_metrics_endpoint_can_require_a_token() -> None:
    with make_client(metrics_token=METRICS_TOKEN) as client:
        assert client.get("/metrics").status_code == 401
        wrong = client.get("/metrics", headers={"authorization": "Bearer " + "x" * 23})
        assert wrong.status_code == 401
        assert client.get("/metrics", headers={"authorization": "Basic abc"}).status_code == 401
        assert "mcp_warden_build_info" in scrape(client, authorization=f"Bearer {METRICS_TOKEN}")


def test_metrics_token_must_be_long_enough() -> None:
    from pydantic import ValidationError

    from mcp_warden.config import Settings

    with pytest.raises(ValidationError, match="WARDEN_METRICS_TOKEN"):
        Settings(metrics_token="short")  # noqa: S106 - too short on purpose


def test_metrics_can_be_turned_off() -> None:
    with make_client(metrics_enabled=False) as client:
        assert client.get("/metrics").status_code == 404
        assert client.app.state.metrics is None  # type: ignore[attr-defined]
        headers = {**initialize(client), "x-warden-agent": "bot"}
        assert "result" in call(client, headers, "add", a=1, b=2)


def test_each_gateway_has_its_own_registry() -> None:
    with make_client() as one, make_client() as two:
        headers = {**initialize(one), "x-warden-agent": "bot"}
        call(one, headers, "add", a=1, b=2)
        assert 'tool="add"' in scrape(one)
        assert 'tool="add"' not in scrape(two)


def test_a_lost_upstream_session_is_its_own_failure_kind() -> None:
    metrics = GatewayMetrics()
    with make_client(metrics=metrics) as client:
        headers = {
            "x-warden-agent": "bot",
            "mcp-session-id": "expired-session",
            "mcp-protocol-version": "2025-11-25",
        }
        assert client.post("/mcp/demo", json=rpc(1, "ping"), headers=headers).status_code == 404
    assert (
        sample(metrics, "mcp_warden_upstream_requests_total", server="demo", result="session_lost")
        == 1
    )


def test_failure_kinds() -> None:
    from mcp_warden.observability.metrics import SESSION_LOST
    from mcp_warden.proxy import UpstreamSessionNotFoundError
    from mcp_warden.proxy.instrumented import failure_kind

    assert failure_kind(UpstreamSessionNotFoundError("demo")) == SESSION_LOST
    assert failure_kind(JsonRpcError(ErrorCode.INTERNAL_ERROR, "x")) == "error"
