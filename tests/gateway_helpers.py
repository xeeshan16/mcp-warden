"""Shared helpers for gateway tests: an app in front of the fake upstream."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
from fastapi.testclient import TestClient

from mcp_warden.app import create_app
from mcp_warden.config import AuthMode, Settings
from mcp_warden.fake_upstream import create_fake_upstream
from mcp_warden.policy import Effect, Policy, PolicyEngine
from mcp_warden.proxy import HttpUpstreamClient
from mcp_warden.upstreams import Upstream, UpstreamRegistry

EXAMPLE_POLICY = Path(__file__).resolve().parents[1] / "examples" / "policy.yaml"

INIT = {
    "jsonrpc": "2.0",
    "id": 0,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "test-agent", "version": "1"},
    },
}


def allow_all() -> PolicyEngine:
    return PolicyEngine(Policy(version=1, default=Effect.ALLOW))


def make_client(
    *,
    sse: bool = False,
    timeout: float = 2.0,
    engine: PolicyEngine | None = None,
    **settings: Any,
) -> TestClient:
    """Gateway in front of the fake upstream; the policy allows everything
    unless a test passes its own engine (policy behaviour has its own tests)."""
    fake = create_fake_upstream(sse=sse)
    transport = HttpUpstreamClient(httpx.AsyncClient(transport=httpx.ASGITransport(app=fake)))
    registry = UpstreamRegistry([Upstream("demo", "http://upstream.test/mcp", timeout, 1.0, {})])
    app = create_app(
        Settings(
            policy_path=EXAMPLE_POLICY,
            upstreams_path=None,
            auth_mode=AuthMode.TRUSTED_HEADER,
            **settings,
        ),
        engine=engine or allow_all(),
        upstreams=registry,
        transport=transport,
    )
    return TestClient(app)


def initialize(client: TestClient) -> dict[str, str]:
    resp = client.post("/mcp/demo", json=INIT)
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == 0
    assert body["result"]["serverInfo"]["name"] == "mcp-warden-fake-upstream"
    return {"mcp-session-id": resp.headers["mcp-session-id"], "mcp-protocol-version": "2025-11-25"}


def rpc(request_id: Any, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        msg["params"] = params
    return msg
