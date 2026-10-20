"""The admin API for agents, keys and usage, end to end against the identity database."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from conftest import FakeClock
from gateway_helpers import ADMIN_HEADERS, ADMIN_TOKEN, INIT, make_client, rpc
from mcp_warden.app import create_app
from mcp_warden.budget import Charge, InMemoryUsageStore
from mcp_warden.config import AuthMode, Settings, UsageStoreKind
from mcp_warden.fake_upstream import create_fake_upstream
from mcp_warden.policy import Budget, BudgetWindow, LimitScope
from mcp_warden.proxy import HttpUpstreamClient
from mcp_warden.upstreams import Upstream, UpstreamRegistry

POLICY = """\
version: 1
default: allow
rules:
  - id: no-deletes
    effect: deny
    tools: ["delete_*"]
budgets:
  - id: daily-calls
    window: day
    max_calls: 100
"""


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY, encoding="utf-8")
    return path


def gateway(db_url: str, policy_file: Path, **settings: Any) -> TestClient:
    transport = HttpUpstreamClient(
        httpx.AsyncClient(transport=httpx.ASGITransport(app=create_fake_upstream()))
    )
    settings.setdefault("auth_mode", AuthMode.API_KEY)
    cfg = Settings(
        policy_path=policy_file,
        upstreams_path=None,
        database_url=db_url,
        admin_token=ADMIN_TOKEN,
        usage_store=UsageStoreKind.DATABASE,
        **settings,
    )
    registry = UpstreamRegistry([Upstream("demo", "http://upstream.test/mcp", 2.0, 1.0, {})])
    return TestClient(create_app(cfg, upstreams=registry, transport=transport))


@pytest.fixture
def client(db_url: str, db_engine: Engine, policy_file: Path) -> Iterator[TestClient]:
    with gateway(db_url, policy_file) as c:
        yield c


def admin(client: TestClient, method: str, path: str, **kwargs: Any) -> httpx.Response:
    return client.request(method, path, headers=ADMIN_HEADERS, **kwargs)


def new_key(client: TestClient, agent: str = "support-bot", **body: Any) -> dict[str, Any]:
    resp = admin(client, "POST", f"/v1/agents/{agent}/keys", json=body)
    assert resp.status_code == 201, resp.text
    issued: dict[str, Any] = resp.json()
    return issued


def connect(client: TestClient, key: str) -> httpx.Response:
    return client.post("/mcp/demo", json=INIT, headers={"authorization": f"Bearer {key}"})


def echo(client: TestClient, key: str) -> httpx.Response:
    headers = {"authorization": f"Bearer {key}"}
    init = client.post("/mcp/demo", json=INIT, headers=headers)
    headers["mcp-session-id"] = init.headers["mcp-session-id"]
    headers["mcp-protocol-version"] = "2025-11-25"
    call = rpc(1, "tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    return client.post("/mcp/demo", json=call, headers=headers)


def test_onboard_an_agent_entirely_over_http(client: TestClient) -> None:
    created = admin(
        client, "POST", "/v1/agents", json={"name": "support-bot", "description": "Tier 1"}
    )
    assert created.status_code == 201
    assert created.json()["name"] == "support-bot"
    assert created.json()["disabled"] is False

    issued = new_key(client, label="laptop", expires_in_days=30)
    assert issued["key"].startswith("mcpw_")
    assert issued["status"] == "active"
    assert issued["label"] == "laptop"
    assert issued["expires_at"] is not None
    assert connect(client, issued["key"]).status_code == 200

    view = admin(client, "GET", "/v1/agents/support-bot").json()
    assert view["description"] == "Tier 1"
    assert [k["prefix"] for k in view["keys"]] == [issued["prefix"]]
    assert view["keys"][0]["last_used_at"] is not None
    # The plaintext is never shown again.
    assert issued["key"] not in str(view)
    assert issued["key"] not in admin(client, "GET", "/v1/agents/support-bot/keys").text
    names = [a["name"] for a in admin(client, "GET", "/v1/agents").json()["agents"]]
    assert names == ["support-bot"]


def test_issued_keys_are_not_cached(client: TestClient) -> None:
    admin(client, "POST", "/v1/agents", json={"name": "support-bot"})
    resp = admin(client, "POST", "/v1/agents/support-bot/keys", json={})
    assert resp.headers["cache-control"] == "no-store"


def test_disable_enable_and_revoke_take_effect_immediately(client: TestClient) -> None:
    admin(client, "POST", "/v1/agents", json={"name": "support-bot"})
    key = new_key(client)
    assert connect(client, key["key"]).status_code == 200

    disabled = admin(client, "POST", "/v1/agents/support-bot/disable")
    assert disabled.json()["disabled"] is True
    assert connect(client, key["key"]).status_code == 401
    admin(client, "POST", "/v1/agents/support-bot/enable")
    assert connect(client, key["key"]).status_code == 200

    revoked = admin(client, "POST", f"/v1/keys/{key['prefix']}/revoke").json()
    assert revoked["status"] == "revoked"
    assert connect(client, key["key"]).status_code == 401
    again = admin(client, "POST", f"/v1/keys/{key['prefix']}/revoke").json()
    assert again["revoked_at"] == revoked["revoked_at"]
    # Other keys of the agent are unaffected.
    assert connect(client, new_key(client)["key"]).status_code == 200


@pytest.mark.parametrize(
    ("method", "path", "body", "status"),
    [
        ("POST", "/v1/agents", {"name": "support-bot"}, 409),
        ("POST", "/v1/agents", {"name": "anonymous"}, 422),
        ("POST", "/v1/agents", {"name": "has space"}, 422),
        ("POST", "/v1/agents", {"name": "x", "description": "d" * 501}, 422),
        ("GET", "/v1/agents/nobody", None, 404),
        ("POST", "/v1/agents/nobody/disable", None, 404),
        ("POST", "/v1/agents/nobody/enable", None, 404),
        ("GET", "/v1/agents/nobody/keys", None, 404),
        ("POST", "/v1/agents/nobody/keys", {}, 404),
        ("POST", "/v1/agents/support-bot/keys", {"expires_in_days": 0}, 422),
        ("POST", "/v1/agents/support-bot/keys", {"label": "l" * 101}, 422),
        ("POST", "/v1/keys/mcpw_nope/revoke", None, 404),
        ("GET", f"/v1/agents/{'a' * 101}", None, 422),
        ("GET", "/v1/usage?limit=0", None, 422),
    ],
)
def test_bad_requests_get_precise_errors(
    client: TestClient, method: str, path: str, body: dict[str, Any] | None, status: int
) -> None:
    admin(client, "POST", "/v1/agents", json={"name": "support-bot"})
    resp = admin(client, method, path, json=body)
    assert resp.status_code == status, resp.text


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/v1/agents"),
        ("POST", "/v1/agents"),
        ("GET", "/v1/agents/a"),
        ("POST", "/v1/agents/a/disable"),
        ("POST", "/v1/agents/a/enable"),
        ("GET", "/v1/agents/a/keys"),
        ("POST", "/v1/agents/a/keys"),
        ("POST", "/v1/keys/p/revoke"),
        ("GET", "/v1/usage"),
    ],
)
def test_every_endpoint_needs_an_admin(client: TestClient, method: str, path: str) -> None:
    assert client.request(method, path, json={"name": "a"}).status_code == 401
    wrong = {"authorization": "Bearer mcpw_not_an_admin_token"}
    assert client.request(method, path, json={"name": "a"}, headers=wrong).status_code == 401


def test_agent_endpoints_are_absent_without_the_identity_database() -> None:
    with make_client(admin_token=ADMIN_TOKEN) as client:
        resp = client.get("/v1/agents", headers=ADMIN_HEADERS)
    assert resp.status_code == 404
    assert "WARDEN_AUTH_MODE=api-key" in resp.json()["detail"]


def test_usage_view_reports_counters_with_the_limits_in_force(
    client: TestClient, policy_file: Path
) -> None:
    for agent in ("support-bot", "triage-bot"):
        admin(client, "POST", "/v1/agents", json={"name": agent})
    support = new_key(client)["key"]
    triage = new_key(client, "triage-bot")["key"]
    for _ in range(2):
        assert "result" in echo(client, support).json()
    assert "result" in echo(client, triage).json()

    usage = admin(client, "GET", "/v1/usage").json()["usage"]
    assert [(u["agent"], u["budget"], u["calls"]) for u in usage] == [
        ("support-bot", "daily-calls", 2),
        ("triage-bot", "daily-calls", 1),
    ]
    assert usage[0]["max_calls"] == 100
    assert usage[0]["max_tokens"] is None
    assert usage[0]["server"] is None
    only = admin(client, "GET", "/v1/usage?agent=triage-bot&limit=5").json()["usage"]
    assert [u["agent"] for u in only] == ["triage-bot"]

    # Once the budget is removed from the policy its counters show no limit.
    policy_file.write_text(POLICY.split("budgets:")[0], encoding="utf-8")
    assert admin(client, "POST", "/v1/policy/reload").json()["changed"] is True
    after = admin(client, "GET", "/v1/usage?all=true").json()["usage"]
    assert {u["max_calls"] for u in after} == {None}


def test_usage_view_works_with_the_memory_store() -> None:
    with make_client(admin_token=ADMIN_TOKEN) as client:
        assert client.get("/v1/usage", headers=ADMIN_HEADERS).json() == {"usage": []}


def test_usage_view_needs_a_reporting_store() -> None:
    class Silent:
        async def reserve(self, charges: Any, tokens: int) -> None:
            return None

        async def settle(self, charges: Any, tokens: int) -> None:
            return None

    with make_client(admin_token=ADMIN_TOKEN, usage_ledger=Silent()) as client:
        assert client.get("/v1/usage", headers=ADMIN_HEADERS).status_code == 404


# -- the in-memory ledger's report --------------------------------------------


def _charge(clock: FakeClock, agent: str, budget: str, hours: int = 0) -> Charge:
    from datetime import timedelta

    start = clock.now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=hours)
    spec = Budget(id=budget, window=BudgetWindow.HOUR, max_calls=10, scope=LimitScope.AGENT)
    return Charge(spec, agent, None, None, start, start + timedelta(hours=1))


def test_memory_store_reports_open_windows_newest_first(clock: FakeClock) -> None:
    store = InMemoryUsageStore(clock=clock)
    store.reserve_sync([_charge(clock, "b", "calls")], 0)
    store.reserve_sync([_charge(clock, "a", "calls")], 7)
    store.reserve_sync([_charge(clock, "a", "calls")], 0)
    store.reserve_sync([_charge(clock, "a", "calls", hours=2)], 0)

    current = store.records()
    assert [(r.agent, r.calls, r.tokens) for r in current] == [("a", 2, 7), ("b", 1, 0)]
    everything = store.records(current_only=False)
    assert [r.agent for r in everything] == ["a", "b", "a"]
    assert everything[-1].window_end <= clock.now
    assert [r.agent for r in store.records(agent="b")] == ["b"]
    assert len(store.records(current_only=False, limit=1)) == 1
