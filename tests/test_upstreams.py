from __future__ import annotations

from pathlib import Path

import pytest

from mcp_warden.upstreams import UpstreamError, load_upstreams, load_upstreams_file

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "upstreams.yaml"

VALID = """
version: 1
servers:
  - name: github
    url: https://mcp.example.test/github/mcp
    timeout_seconds: 12.5
    headers_from_env:
      Authorization: GH_MCP_AUTH
  - name: tickets
    url: http://127.0.0.1:9001/mcp
"""


def test_example_file_loads() -> None:
    registry = load_upstreams_file(EXAMPLE, env={})
    assert registry.names() == ["demo"]
    demo = registry.get("demo")
    assert demo is not None
    assert demo.url == "http://127.0.0.1:9001/mcp"
    assert demo.timeout_seconds == 10


def test_resolves_headers_from_env() -> None:
    registry = load_upstreams(VALID, env={"GH_MCP_AUTH": "Bearer synthetic-test-value"})
    assert len(registry) == 2
    github = registry.get("github")
    assert github is not None
    assert github.headers == {"Authorization": "Bearer synthetic-test-value"}
    assert github.timeout_seconds == 12.5
    tickets = registry.get("tickets")
    assert tickets is not None
    assert tickets.timeout_seconds == 30.0
    assert dict(tickets.headers) == {}
    assert [u.name for u in registry] == ["github", "tickets"]


def test_repr_never_contains_credentials() -> None:
    registry = load_upstreams(VALID, env={"GH_MCP_AUTH": "Bearer synthetic-test-value"})
    assert "synthetic-test-value" not in repr(registry.get("github"))


def test_missing_env_var_fails_at_load() -> None:
    with pytest.raises(UpstreamError, match="GH_MCP_AUTH"):
        load_upstreams(VALID, env={})


def test_unknown_server_is_none() -> None:
    assert load_upstreams(VALID, env={"GH_MCP_AUTH": "x"}).get("nope") is None


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("- 1\n", "mapping"),
        ("version: 2\nservers: []\n", "version"),
        ("version: 1\nservers:\n  - name: a\n    url: ftp://x/mcp\n", "url"),
        ("version: 1\nservers:\n  - name: a b\n    url: http://x/mcp\n", "name"),
        (
            "version: 1\nservers:\n  - {name: a, url: 'http://x/mcp'}\n"
            "  - {name: a, url: 'http://y/mcp'}\n",
            "duplicate",
        ),
        (
            "version: 1\nservers:\n  - {name: a, url: 'http://x/mcp', timeout_seconds: 0}\n",
            "timeout",
        ),
        ("version: 1\nservers:\n  - {name: a, url: 'http://x/mcp', extra: 1}\n", "extra"),
        (
            "version: 1\nservers:\n  - name: a\n    url: http://x/mcp\n"
            "    headers_from_env: {Mcp-Session-Id: S}\n",
            "managed by the gateway",
        ),
        (
            "version: 1\nservers:\n  - name: a\n    url: http://x/mcp\n"
            "    headers_from_env: {'Bad Header': S}\n",
            "invalid header",
        ),
        (
            "version: 1\nservers:\n  - name: a\n    url: http://x/mcp\n"
            "    headers_from_env: {X-Key: '1BAD'}\n",
            "environment variable",
        ),
        ("version: 1\nservers: [\n", "YAML"),
    ],
)
def test_rejects_invalid_documents(text: str, message: str) -> None:
    with pytest.raises(UpstreamError, match=message):
        load_upstreams(text, env={})


def test_size_cap() -> None:
    with pytest.raises(UpstreamError, match="exceeds"):
        load_upstreams("#" * 300_000, env={})


def test_unreadable_file(tmp_path: Path) -> None:
    with pytest.raises(UpstreamError, match="cannot read"):
        load_upstreams_file(tmp_path / "missing.yaml", env={})
