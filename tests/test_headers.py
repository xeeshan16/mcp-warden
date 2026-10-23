"""Header hygiene, Origin checks, security headers and request size limits."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.datastructures import Headers

from gateway_helpers import ADMIN_HEADERS, ADMIN_TOKEN, initialize, make_client, rpc
from mcp_warden.app import SECURITY_HEADERS, create_app
from mcp_warden.config import AuthMode, Settings
from mcp_warden.jsonrpc import ErrorCode
from mcp_warden.observability.metrics import GatewayMetrics
from mcp_warden.proxy import HttpUpstreamClient
from mcp_warden.proxy.headers import (
    HeaderError,
    forwarded_headers,
    origin_allowed,
    valid_protocol_version,
    valid_session_id,
)
from mcp_warden.upstreams import Upstream, UpstreamRegistry

# --- Forwarded headers ----------------------------------------------------------


def test_only_the_two_mcp_headers_cross() -> None:
    headers = {
        "Mcp-Session-Id": "abc-123",
        "MCP-Protocol-Version": "2025-11-25",
        "Authorization": "Bearer agent-key",
        "Cookie": "a=b",
        "X-Forwarded-For": "10.0.0.1",
    }
    assert forwarded_headers(headers) == {
        "mcp-session-id": "abc-123",
        "mcp-protocol-version": "2025-11-25",
    }
    assert forwarded_headers({}) == {}


@pytest.mark.parametrize(
    "value",
    ["", "has space", "tab\there", "ünïcode", "x" * 1025, "semi;colon\x7f"],
)
def test_invalid_session_ids(value: str) -> None:
    assert not valid_session_id(value)
    with pytest.raises(HeaderError, match="invalid mcp-session-id"):
        forwarded_headers({"mcp-session-id": value})


@pytest.mark.parametrize("value", ["a", "!~", "x" * 1024, "eyJhbGciOi.J9.sig-_="])
def test_valid_session_ids(value: str) -> None:
    assert valid_session_id(value)


@pytest.mark.parametrize("value", ["", "0", "latest", "2025-6-18", "2025-06-18 ", "2025-06-18x"])
def test_invalid_protocol_versions(value: str) -> None:
    assert not valid_protocol_version(value)
    with pytest.raises(HeaderError, match="invalid mcp-protocol-version"):
        forwarded_headers({"mcp-protocol-version": value})


def test_repeated_headers_are_refused() -> None:
    raw = [(b"mcp-session-id", b"one"), (b"Mcp-Session-Id", b"two")]
    with pytest.raises(HeaderError, match="must not be repeated"):
        forwarded_headers(Headers(raw=raw))


@pytest.mark.parametrize(
    ("origin", "allowed", "ok"),
    [
        (None, [], True),
        ("https://evil.example", [], False),
        ("null", [], False),
        ("https://app.example", ["https://app.example"], True),
        ("HTTPS://App.Example", ["https://app.example"], True),
        ("https://app.example.evil", ["https://app.example"], False),
        ("null", ["null"], True),
    ],
)
def test_origin_allowed(origin: str | None, allowed: list[str], ok: bool) -> None:
    assert origin_allowed(origin, allowed) is ok


# --- Through the gateway ----------------------------------------------------------


@pytest.fixture
def metrics() -> GatewayMetrics:
    return GatewayMetrics()


@pytest.fixture
def client(metrics: GatewayMetrics) -> Iterator[TestClient]:
    with make_client(metrics=metrics, admin_token=ADMIN_TOKEN) as c:
        yield c


def _rejections(metrics: GatewayMetrics, reason: str) -> float:
    value = metrics.registry.get_sample_value(
        "mcp_warden_http_rejections_total", {"reason": reason}
    )
    return value or 0.0


def test_malformed_protocol_version_is_a_bad_request(
    client: TestClient, metrics: GatewayMetrics
) -> None:
    headers = initialize(client)
    headers["mcp-protocol-version"] = "0"
    resp = client.post("/mcp/demo", json=rpc(1, "ping"), headers=headers)
    assert resp.status_code == 400
    assert resp.json()["error"] == {
        "code": ErrorCode.INVALID_REQUEST,
        "message": "invalid mcp-protocol-version header",
    }
    assert _rejections(metrics, "invalid_header") == 1


def test_a_bogus_version_can_no_longer_unlock_batches(client: TestClient) -> None:
    # "0" sorts before "2025-06-18" and used to count as an old revision.
    headers = initialize(client)
    headers["mcp-protocol-version"] = "0"
    resp = client.post("/mcp/demo", json=[rpc(1, "ping"), rpc(2, "ping")], headers=headers)
    assert resp.status_code == 400


def test_repeated_session_header_is_a_bad_request(client: TestClient) -> None:
    session = initialize(client)["mcp-session-id"]
    resp = client.post(
        "/mcp/demo",
        content=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
        headers=[
            ("content-type", "application/json"),
            ("mcp-session-id", session),
            ("mcp-session-id", "fake-session-999"),
        ],
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["message"] == "mcp-session-id must not be repeated"


@pytest.mark.parametrize("method", ["POST", "GET", "DELETE"])
def test_browser_origins_are_refused(
    client: TestClient, metrics: GatewayMetrics, method: str
) -> None:
    resp = client.request(
        method,
        "/mcp/demo",
        json=rpc(1, "ping"),
        headers={"origin": "https://evil.example"},
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["message"] == "origin not allowed"
    assert _rejections(metrics, "origin_not_allowed") == 1


def test_allowed_origins_are_configurable() -> None:
    with make_client(allowed_origins=["https://console.example"]) as c:
        ok = c.post(
            "/mcp/demo",
            json=rpc(
                1,
                "initialize",
                {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "t", "version": "1"},
                },
            ),
            headers={"origin": "https://console.example"},
        )
        refused = c.post("/mcp/demo", json=rpc(1, "ping"), headers={"origin": "https://x.example"})
    assert ok.status_code == 200
    assert refused.status_code == 403


def test_invalid_upstream_session_id_is_not_relayed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": 1, "result": {}},
            headers={"mcp-session-id": "bad session id"},
        )

    transport = HttpUpstreamClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    app = create_app(
        Settings(upstreams_path=None, auth_mode=AuthMode.TRUSTED_HEADER),
        upstreams=UpstreamRegistry([Upstream("demo", "http://upstream.test/mcp", 2.0, 1.0, {})]),
        transport=transport,
    )
    with TestClient(app) as c:
        resp = c.post("/mcp/demo", json=rpc(1, "ping"))
    assert resp.status_code == 200
    assert "mcp-session-id" not in resp.headers
    assert resp.json()["error"]["code"] == ErrorCode.UPSTREAM_ERROR
    assert resp.json()["error"]["message"] == "upstream sent an invalid session id"


# --- Security headers ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("GET", "/healthz", None),
        ("GET", "/no-such-route", None),
        ("GET", "/v1/policy", None),
        ("POST", "/mcp/demo", rpc(1, "ping")),
        ("POST", "/mcp/unknown", rpc(1, "ping")),
    ],
)
def test_every_response_carries_security_headers(
    client: TestClient, method: str, path: str, body: Any
) -> None:
    resp = client.request(method, path, json=body)
    for name, value in SECURITY_HEADERS:
        assert resp.headers[name.decode()] == value.decode()


def test_security_headers_are_not_duplicated(client: TestClient) -> None:
    resp = client.get("/healthz")
    assert resp.headers.get_list("cache-control") == ["no-store"]


# --- Request size limits ------------------------------------------------------------------


def test_admin_bodies_are_capped_by_content_length() -> None:
    with make_client(admin_token=ADMIN_TOKEN, max_request_bytes=1024) as c:
        small = c.post(
            "/v1/policy/evaluate",
            json={"agent": "a", "server": "demo", "tool": "echo"},
            headers=ADMIN_HEADERS,
        )
        large = c.post(
            "/v1/policy/evaluate",
            json={"agent": "a", "server": "demo", "tool": "echo", "arguments": {"x": "y" * 2000}},
            headers=ADMIN_HEADERS,
        )
    assert small.status_code == 200
    assert large.status_code == 413
    assert large.json() == {"detail": "request body too large"}
    assert large.headers["x-content-type-options"] == "nosniff"


def test_chunked_admin_bodies_are_capped_while_streaming() -> None:
    def chunks() -> Iterator[bytes]:
        yield b'{"agent": "a", "server": "demo", "tool": "echo", "arguments": {"x": "'
        for _ in range(10):
            yield b"y" * 512
        yield b'"}}'

    with make_client(admin_token=ADMIN_TOKEN, max_request_bytes=1024) as c:
        resp = c.post(
            "/v1/policy/evaluate",
            content=chunks(),
            headers={**ADMIN_HEADERS, "content-type": "application/json"},
        )
    assert resp.status_code == 413


def test_the_mcp_endpoint_keeps_its_own_limit() -> None:
    text = "z" * 5000
    with make_client(max_request_bytes=1024) as c:
        headers = initialize(c)
        payload = rpc(1, "tools/call", {"name": "echo", "arguments": {"text": text}})
        resp = c.post("/mcp/demo", json=payload, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["result"]["content"][0]["text"] == text
