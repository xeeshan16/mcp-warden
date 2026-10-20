"""Hot reload of the policy file: the reloader on its own and through the gateway."""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from pathlib import Path

import anyio
import httpx
import pytest
from fastapi.testclient import TestClient

from conftest import FakeClock
from gateway_helpers import ADMIN_HEADERS, ADMIN_TOKEN, initialize, rpc
from mcp_warden.app import create_app
from mcp_warden.config import AuthMode, Settings
from mcp_warden.fake_upstream import create_fake_upstream
from mcp_warden.jsonrpc import ErrorCode
from mcp_warden.policy import Effect, PolicyEngine, PolicyError, PolicyReloader, ToolCallRequest
from mcp_warden.policy.loader import MAX_POLICY_BYTES
from mcp_warden.proxy import HttpUpstreamClient
from mcp_warden.upstreams import Upstream, UpstreamRegistry

OPEN = """\
version: 1
default: deny
rules:
  - id: echo-for-all
    effect: allow
    tools: ["echo"]
  - id: tickets
    effect: allow
    tools: ["create_ticket"]
rate_limits:
  - id: per-agent
    requests: 100
    per: minute
"""

TIGHTER = """\
version: 1
default: deny
rules:
  - id: echo-for-all
    effect: deny
    description: Echo is switched off during the incident.
    tools: ["echo"]
  - id: reads
    effect: allow
    tools: ["get_*"]
rate_limits:
  - id: per-agent
    requests: 10
    per: minute
budgets:
  - id: daily
    max_calls: 50
    window: day
"""

ECHO = ToolCallRequest("bot", "demo", "echo")


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(OPEN, encoding="utf-8")
    return path


@pytest.fixture
def reloader(policy_file: Path, clock: FakeClock) -> PolicyReloader:
    return PolicyReloader.from_file(policy_file, clock=clock)


def test_initial_load_records_the_source(reloader: PolicyReloader, policy_file: Path) -> None:
    status = reloader.status()
    assert status["path"] == str(policy_file)
    assert status["sha256"] is not None
    assert len(status["sha256"]) == 64
    assert status["loaded_at"] == "2026-10-15T09:00:00Z"
    assert status["last_error"] is None
    assert (status["reloads"], status["failed_reloads"]) == (0, 0)


def test_identical_content_is_not_a_reload(reloader: PolicyReloader, policy_file: Path) -> None:
    policy = reloader.engine.policy
    policy_file.write_text(OPEN, encoding="utf-8")
    result = reloader.reload()
    assert not result.changed
    assert result.changes is None
    assert reloader.engine.policy is policy
    assert reloader.status()["reloads"] == 0


def test_a_valid_edit_is_swapped_in_and_described(
    reloader: PolicyReloader, policy_file: Path, clock: FakeClock
) -> None:
    assert reloader.engine.evaluate(ECHO).effect is Effect.ALLOW
    before = reloader.sha256
    policy_file.write_text(TIGHTER, encoding="utf-8")
    clock.now = clock.now.replace(hour=10)
    result = reloader.reload()
    assert result.changed
    assert result.sha256 != before
    decision = reloader.engine.evaluate(ECHO)
    assert (decision.effect, decision.rule_id) == (Effect.DENY, "echo-for-all")
    changes = result.changes
    assert changes is not None
    assert changes.rules.added == ("reads",)
    assert changes.rules.removed == ("tickets",)
    assert changes.rules.changed == ("echo-for-all",)
    assert changes.rate_limits.changed == ("per-agent",)
    assert changes.budgets.added == ("daily",)
    assert not changes.default_changed
    assert changes.describe() == (
        "rules: 1 added, 1 removed, 1 changed; rate limits: 1 changed; budgets: 1 added"
    )
    assert result.to_dict()["changes"]["rules"]["removed"] == ["tickets"]
    status = reloader.status()
    assert status["loaded_at"] == "2026-10-15T10:00:00Z"
    assert status["reloads"] == 1


def test_default_change_is_reported(reloader: PolicyReloader, policy_file: Path) -> None:
    policy_file.write_text(OPEN.replace("default: deny", "default: allow"), encoding="utf-8")
    changes = reloader.reload().changes
    assert changes is not None
    assert changes.default_changed
    assert changes.describe() == "default changed"


def test_reformatting_changes_the_digest_but_nothing_effective(
    reloader: PolicyReloader, policy_file: Path
) -> None:
    policy_file.write_text("# reviewed\n" + OPEN, encoding="utf-8")
    result = reloader.reload()
    assert result.changed
    assert result.changes is not None
    assert not result.changes
    assert result.changes.describe() == "no effective change"


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("version: 1\nrules: [\n", "not valid YAML"),
        ("version: 1\nrules:\n  - id: a\n    effect: nope\n", "invalid policy"),
        ("- just\n- a list\n", "mapping"),
        (b"\xff\xfe", "not UTF-8"),
        ("#" * (MAX_POLICY_BYTES + 1), "exceeds"),
    ],
)
def test_a_broken_file_never_replaces_a_working_policy(
    reloader: PolicyReloader, policy_file: Path, content: str | bytes, message: str
) -> None:
    good = reloader.engine.policy
    digest = reloader.sha256
    if isinstance(content, bytes):
        policy_file.write_bytes(content)
    else:
        policy_file.write_text(content, encoding="utf-8")
    with pytest.raises(PolicyError, match=message):
        reloader.reload()
    assert reloader.engine.policy is good
    assert reloader.sha256 == digest
    status = reloader.status()
    assert message in status["last_error"]
    assert status["failed_reloads"] == 1
    # Fixing the file clears the error.
    policy_file.write_text(TIGHTER, encoding="utf-8")
    assert reloader.reload().changed
    assert reloader.status()["last_error"] is None


def test_a_missing_file_keeps_the_policy(reloader: PolicyReloader, policy_file: Path) -> None:
    policy_file.unlink()
    with pytest.raises(PolicyError, match="cannot read"):
        reloader.reload()
    assert reloader.engine.evaluate(ECHO).allowed


def test_a_missing_file_fails_startup(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="cannot read"):
        PolicyReloader.from_file(tmp_path / "nope.yaml")


def test_check_logs_instead_of_raising(
    reloader: PolicyReloader, policy_file: Path, caplog: pytest.LogCaptureFixture
) -> None:
    policy_file.write_text("version: 1\nrules: [\n", encoding="utf-8")
    with caplog.at_level(logging.ERROR, logger="mcp_warden.policy.reload"):
        assert reloader.check() is None
    assert "keeping the current policy" in caplog.text
    policy_file.write_text(TIGHTER, encoding="utf-8")
    result = reloader.check()
    assert result is not None
    assert result.changed


def test_an_engine_built_elsewhere_reloads_on_first_request(policy_file: Path) -> None:
    engine = PolicyEngine(PolicyReloader.from_file(policy_file).engine.policy)
    reloader = PolicyReloader(engine, policy_file)
    assert reloader.status()["sha256"] is None
    assert reloader.reload().changed
    assert reloader.reload().changed is False


@pytest.mark.anyio
async def test_the_watcher_picks_up_edits(reloader: PolicyReloader, policy_file: Path) -> None:
    async with anyio.create_task_group() as tg:
        tg.start_soon(reloader.run_periodically, 0.01)
        policy_file.write_text(TIGHTER, encoding="utf-8")
        with anyio.fail_after(5):
            while reloader.engine.evaluate(ECHO).allowed:
                await anyio.sleep(0.01)
        tg.cancel_scope.cancel()
    assert reloader.status()["reloads"] == 1


# -- through the gateway ------------------------------------------------------


def gateway(policy_file: Path, **settings: object) -> TestClient:
    fake = create_fake_upstream()
    transport = HttpUpstreamClient(httpx.AsyncClient(transport=httpx.ASGITransport(app=fake)))
    app = create_app(
        Settings(
            policy_path=policy_file,
            upstreams_path=None,
            auth_mode=AuthMode.TRUSTED_HEADER,
            admin_token=ADMIN_TOKEN,
            **settings,  # type: ignore[arg-type]
        ),
        upstreams=UpstreamRegistry([Upstream("demo", "http://upstream.test/mcp", 2.0, 1.0, {})]),
        transport=transport,
    )
    return TestClient(app)


@pytest.fixture
def client(policy_file: Path) -> Iterator[TestClient]:
    with gateway(policy_file) as c:
        yield c


def echo(client: TestClient, headers: dict[str, str]) -> dict[str, object]:
    body: dict[str, object] = client.post(
        "/mcp/demo",
        json=rpc(1, "tools/call", {"name": "echo", "arguments": {"text": "hi"}}),
        headers=headers,
    ).json()
    return body


def session(client: TestClient) -> dict[str, str]:
    headers = initialize(client)
    headers["x-warden-agent"] = "bot"
    return headers


def test_reload_endpoint_applies_a_new_policy_to_live_sessions(
    client: TestClient, policy_file: Path
) -> None:
    headers = session(client)
    assert "result" in echo(client, headers)
    policy_file.write_text(TIGHTER, encoding="utf-8")
    resp = client.post("/v1/policy/reload", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    body = resp.json()
    assert body["changed"] is True
    assert body["changes"]["rules"]["changed"] == ["echo-for-all"]
    assert body["policy"]["budget_ids"] == ["daily"]
    assert body["policy"]["source"]["reloads"] == 1
    # The same session, no reconnect: the next call meets the new rule.
    error = echo(client, headers)["error"]
    assert isinstance(error, dict)
    assert error["code"] == ErrorCode.POLICY_DENIED
    # Nothing changed since: a second reload is a no-op.
    again = client.post("/v1/policy/reload", headers=ADMIN_HEADERS).json()
    assert again["changed"] is False


def test_an_invalid_file_is_refused_and_reported(client: TestClient, policy_file: Path) -> None:
    headers = session(client)
    policy_file.write_text("version: 1\nrules:\n  - id: a\n    effect: nope\n", encoding="utf-8")
    resp = client.post("/v1/policy/reload", headers=ADMIN_HEADERS)
    assert resp.status_code == 422
    assert "invalid policy" in resp.json()["detail"]
    assert "result" in echo(client, headers)
    source = client.get("/v1/policy", headers=ADMIN_HEADERS).json()["source"]
    assert "invalid policy" in source["last_error"]
    assert source["failed_reloads"] == 1


def test_reload_needs_an_admin(client: TestClient) -> None:
    assert client.post("/v1/policy/reload").status_code == 401


def test_the_gateway_watches_the_file_when_asked(policy_file: Path) -> None:
    with gateway(policy_file, policy_reload_interval_seconds=0.02) as client:
        headers = session(client)
        assert "result" in echo(client, headers)
        policy_file.write_text(TIGHTER, encoding="utf-8")
        deadline = time.monotonic() + 5
        while "result" in echo(client, headers):
            assert time.monotonic() < deadline, "policy file change was not picked up"
            time.sleep(0.02)
        source = client.get("/v1/policy", headers=ADMIN_HEADERS).json()["source"]
        assert source["reloads"] == 1
