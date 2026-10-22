"""The scripted demo agent, run against an in-process gateway on the example policy."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from gateway_helpers import ADMIN_TOKEN, EXAMPLE_POLICY
from mcp_warden.__main__ import main
from mcp_warden.app import create_app
from mcp_warden.config import ApprovalStoreKind, AuditStoreKind, AuthMode, Settings
from mcp_warden.demo import Demo, DemoError
from mcp_warden.fake_upstream import create_fake_upstream
from mcp_warden.proxy import HttpUpstreamClient
from mcp_warden.ratelimit import InMemoryBucketStore
from mcp_warden.upstreams import Upstream, UpstreamRegistry


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def gateway(db_url: str, policy: Path, clock: Clock, **settings: Any) -> TestClient:
    transport = HttpUpstreamClient(
        httpx.AsyncClient(transport=httpx.ASGITransport(app=create_fake_upstream()))
    )
    cfg = Settings(
        policy_path=policy,
        upstreams_path=None,
        database_url=db_url,
        auth_mode=AuthMode.API_KEY,
        admin_token=ADMIN_TOKEN,
        approval_store=ApprovalStoreKind.DATABASE,
        audit_store=AuditStoreKind.DATABASE,
        **settings,
    )
    registry = UpstreamRegistry([Upstream("demo", "http://upstream.test/mcp", 2.0, 1.0, {})])
    app = create_app(
        cfg, upstreams=registry, transport=transport, bucket_store=InMemoryBucketStore(clock)
    )
    return TestClient(app)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def client(db_url: str, db_engine: Engine, clock: Clock) -> Iterator[TestClient]:
    with gateway(db_url, EXAMPLE_POLICY, clock) as c:
        yield c


def run_demo(client: httpx.Client, clock: Clock, **kwargs: Any) -> tuple[Demo, list[str]]:
    lines: list[str] = []
    demo = Demo(client, ADMIN_TOKEN, out=lines.append, sleep=clock.sleep, **kwargs)
    demo.run()
    return demo, lines


def test_every_step_behaves_as_expected(client: TestClient, clock: Clock) -> None:
    demo, lines = run_demo(client, clock)
    output = "\n".join(lines)

    assert demo.report.ok, output
    assert len(demo.report.passed) == 10
    assert "agent support-bot created" in output
    assert "delete_records is hidden" in output
    assert "-32001 denied by rule never-destructive" in output
    assert "-32001 denied by argument rule short-sleeps-only" in output
    assert "-32002 pending approval apr_" in output
    assert "-32003 rate limited by demo-tickets" in output
    assert "the next call gets HTTP 401" in output
    assert 'effect="deny",rule="never-destructive"' in output
    assert output.endswith("10 of 10 steps behaved as expected")


def test_the_key_never_appears_in_the_output(client: TestClient, clock: Clock) -> None:
    demo, lines = run_demo(client, clock)
    output = "\n".join(lines)

    assert demo._key is not None
    assert demo._key not in output
    assert "mcpw_" not in output


def test_the_audit_table_lists_this_runs_calls(client: TestClient, clock: Clock) -> None:
    _, lines = run_demo(client, clock)
    rows = [line.split() for line in lines if line.startswith("    ") and "B" in line[-6:]]

    assert [row[:2] for row in rows] == [
        ["get_forecast", "forwarded"],
        ["add", "forwarded"],
        ["delete_records", "denied"],
        ["sleep", "denied"],
        ["create_ticket", "approval_pending"],
        ["create_ticket", "forwarded"],
        ["create_ticket", "forwarded"],
        ["create_ticket", "forwarded"],
        ["create_ticket", "rate_limited"],
    ]


def test_a_second_run_reuses_the_agent_and_waits_out_the_rate_limit(
    client: TestClient, clock: Clock
) -> None:
    first, _ = run_demo(client, clock)
    second, lines = run_demo(client, clock)
    output = "\n".join(lines)

    assert first.report.ok
    assert second.report.ok, output
    assert "already exists; reusing it" in output
    assert "rate limited from an earlier run; waiting" in output
    assert first.run_id != second.run_id


def test_a_gateway_that_lets_everything_through_fails_the_demo(
    db_url: str, db_engine: Engine, clock: Clock, tmp_path: Path
) -> None:
    permissive = tmp_path / "allow-all.yaml"
    permissive.write_text("version: 1\ndefault: allow\n", encoding="utf-8")
    with gateway(db_url, permissive, clock) as c:
        demo, lines = run_demo(c, clock)

    assert not demo.report.ok
    assert demo.report.failed == [
        "tools/list only shows what the policy could allow",
        "Denied calls never reach the upstream",
        "A risky call waits for a human",
        "A burst of ticket creation hits the rate limit",
    ]
    assert lines[-1].strip().startswith("6 of 10 steps behaved as expected; failed: ")


def test_a_wrong_admin_token_stops_after_onboarding(client: TestClient, clock: Clock) -> None:
    lines: list[str] = []
    demo = Demo(client, "not-the-admin-token", out=lines.append, sleep=clock.sleep)

    report = demo.run()

    assert report.passed == []
    assert len(report.failed) == 1
    assert "creating the agent: 401" in "\n".join(lines)


def test_metrics_switched_off_are_skipped(db_url: str, db_engine: Engine, clock: Clock) -> None:
    with gateway(db_url, EXAMPLE_POLICY, clock, metrics_enabled=False) as c:
        demo, lines = run_demo(c, clock)

    assert demo.report.ok
    assert "  ✔ metrics are turned off on this gateway; skipped" in lines


def test_a_metrics_token_is_sent(db_url: str, db_engine: Engine, clock: Clock) -> None:
    token = "metrics-token-for-tests"  # noqa: S105 - test fixture, not a secret
    with gateway(db_url, EXAMPLE_POLICY, clock, metrics_token=token) as c:
        without, _ = run_demo(c, clock)
        with_token, _ = run_demo(c, clock, metrics_token=token)

    assert without.report.failed == ["Prometheus metrics count the decisions"]
    assert with_token.report.ok


def test_wait_until_ready_gives_up() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    clock = Clock()
    client = httpx.Client(base_url="http://gateway.test", transport=httpx.MockTransport(refuse))
    demo = Demo(client, ADMIN_TOKEN, out=lambda _: None, sleep=clock.sleep)

    with pytest.raises(DemoError, match="not ready after 0s"):
        demo.wait_until_ready(timeout=0)


def test_cli_needs_an_admin_token(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("WARDEN_ADMIN_TOKEN", raising=False)

    assert main(["demo"]) == 2
    assert "WARDEN_ADMIN_TOKEN" in capsys.readouterr().err


def test_cli_reports_an_unreachable_gateway(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("WARDEN_ADMIN_TOKEN", ADMIN_TOKEN)

    assert main(["demo", "--gateway", "http://127.0.0.1:9", "--wait", "0"]) == 1
    assert "not ready" in capsys.readouterr().err
