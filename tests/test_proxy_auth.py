"""API key authentication end to end: agent → gateway (keys + example policy) → upstream."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from gateway_helpers import EXAMPLE_POLICY, INIT, rpc
from mcp_warden.app import create_app
from mcp_warden.config import AuthMode, Settings
from mcp_warden.db import DatabaseNotReadyError, make_engine
from mcp_warden.fake_upstream import create_fake_upstream
from mcp_warden.identity import IdentityStore
from mcp_warden.jsonrpc import ErrorCode
from mcp_warden.proxy import HttpUpstreamClient
from mcp_warden.upstreams import Upstream, UpstreamRegistry


class RecordingUpstream(httpx.AsyncBaseTransport):
    """The fake upstream behind a transport that records outgoing headers."""

    def __init__(self) -> None:
        super().__init__()
        self.headers: list[httpx.Headers] = []
        self._inner = httpx.ASGITransport(app=create_fake_upstream())

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.headers.append(request.headers)
        return await self._inner.handle_async_request(request)


@pytest.fixture
def upstream() -> RecordingUpstream:
    return RecordingUpstream()


@pytest.fixture
def client(db_url: str, db_engine: Engine, upstream: RecordingUpstream) -> Iterator[TestClient]:
    transport = HttpUpstreamClient(httpx.AsyncClient(transport=upstream))
    registry = UpstreamRegistry([Upstream("demo", "http://upstream.test/mcp", 2.0, 1.0, {})])
    settings = Settings(
        policy_path=EXAMPLE_POLICY,
        upstreams_path=None,
        database_url=db_url,
        auth_mode=AuthMode.API_KEY,
    )
    with TestClient(create_app(settings, upstreams=registry, transport=transport)) as c:
        yield c


def bearer(key: str) -> dict[str, str]:
    return {"authorization": f"Bearer {key}"}


def session(client: TestClient, key: str) -> dict[str, str]:
    resp = client.post("/mcp/demo", json=INIT, headers=bearer(key))
    assert resp.status_code == 200
    return {
        **bearer(key),
        "mcp-session-id": resp.headers["mcp-session-id"],
        "mcp-protocol-version": "2025-11-25",
    }


def listed_tools(client: TestClient, headers: dict[str, str]) -> list[str]:
    body = client.post("/mcp/demo", json=rpc(1, "tools/list"), headers=headers).json()
    return [t["name"] for t in body["result"]["tools"]]


def assert_unauthenticated(resp: httpx.Response) -> dict[str, Any]:
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == 'Bearer realm="mcp-warden"'
    body: dict[str, Any] = resp.json()
    assert body["id"] is None
    assert body["error"]["code"] == ErrorCode.UNAUTHENTICATED
    return body


def test_missing_key_is_refused_before_anything_else(
    client: TestClient, upstream: RecordingUpstream
) -> None:
    assert_unauthenticated(client.post("/mcp/demo", json=INIT))
    # Unknown servers are not revealed to callers without a key.
    assert_unauthenticated(client.post("/mcp/nope", json=INIT))
    assert upstream.headers == []


def test_invalid_key_is_refused(client: TestClient, upstream: RecordingUpstream) -> None:
    body = assert_unauthenticated(client.post("/mcp/demo", json=INIT, headers=bearer("mcpw_x")))
    assert body["error"]["message"] == "invalid, expired or revoked API key"
    assert upstream.headers == []


def test_identity_comes_from_the_key(client: TestClient, store: IdentityStore) -> None:
    store.create_agent("support-bot")
    store.create_agent("intern")
    support = store.issue_key("support-bot").plaintext
    intern = store.issue_key("intern").plaintext
    # The example policy lets only the support bot see create_ticket; a
    # spoofed X-Warden-Agent header is ignored in API key mode.
    assert "create_ticket" in listed_tools(client, session(client, support))
    spoofed = {**session(client, intern), "x-warden-agent": "support-bot"}
    assert "create_ticket" not in listed_tools(client, spoofed)


def test_policy_still_applies(client: TestClient, store: IdentityStore) -> None:
    store.create_agent("bot")
    headers = session(client, store.issue_key("bot").plaintext)
    payload = rpc("d", "tools/call", {"name": "delete_records", "arguments": {"table": "t"}})
    body = client.post("/mcp/demo", json=payload, headers=headers).json()
    assert body["error"]["code"] == ErrorCode.POLICY_DENIED


def test_revocation_takes_effect_immediately(client: TestClient, store: IdentityStore) -> None:
    store.create_agent("bot")
    issued = store.issue_key("bot")
    headers = session(client, issued.plaintext)
    assert listed_tools(client, headers)
    store.revoke_key(issued.info.prefix)
    assert_unauthenticated(client.post("/mcp/demo", json=rpc(2, "tools/list"), headers=headers))


def test_agent_key_is_not_forwarded_upstream(
    client: TestClient, store: IdentityStore, upstream: RecordingUpstream
) -> None:
    store.create_agent("bot")
    key = store.issue_key("bot").plaintext
    listed_tools(client, session(client, key))
    assert upstream.headers
    for sent in upstream.headers:
        assert "authorization" not in sent
        assert key not in str(sent)


def test_gateway_refuses_to_start_on_an_unmigrated_database(tmp_path: Any) -> None:
    url = f"sqlite:///{tmp_path / 'empty.db'}"
    settings = Settings(policy_path=EXAMPLE_POLICY, upstreams_path=None, database_url=url)
    with pytest.raises(DatabaseNotReadyError, match="db upgrade"):
        create_app(settings, upstreams=UpstreamRegistry())
    make_engine(url).dispose()
