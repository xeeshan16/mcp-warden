"""``mcp-warden policy show|reload`` against a gateway's admin API."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from gateway_helpers import ADMIN_TOKEN
from mcp_warden import __main__ as cli
from mcp_warden.__main__ import main
from mcp_warden.app import create_app
from mcp_warden.config import AuthMode, Settings
from test_policy_reload import OPEN, TIGHTER

GATEWAY = "http://gateway.test"


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(OPEN, encoding="utf-8")
    return path


@pytest.fixture
def gateway(policy_file: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Route the CLI's admin client to an in-process gateway; yields the URLs it used."""
    app = create_app(
        Settings(
            policy_path=policy_file,
            upstreams_path=None,
            auth_mode=AuthMode.TRUSTED_HEADER,
            admin_token=ADMIN_TOKEN,
        )
    )
    used: list[str] = []

    def client(base_url: str, token: str) -> httpx.Client:
        used.append(base_url)
        return TestClient(app, base_url=base_url, headers={"authorization": f"Bearer {token}"})

    monkeypatch.setattr(cli, "_admin_client", client)
    monkeypatch.setenv("WARDEN_ADMIN_TOKEN", ADMIN_TOKEN)
    monkeypatch.delenv("WARDEN_GATEWAY_URL", raising=False)
    yield used


def test_show_prints_the_policy_and_its_source(
    gateway: list[str], policy_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["policy", "show", "--gateway", GATEWAY]) == 0
    out = capsys.readouterr().out
    assert "version 1, default deny, 2 rules, 1 rate limits, 0 budgets" in out
    assert f"source {policy_file} (" in out
    assert "last reload failed" not in out
    assert gateway == [GATEWAY]


def test_gateway_url_defaults_from_the_environment(
    gateway: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert main(["policy", "show"]) == 0
    monkeypatch.setenv("WARDEN_GATEWAY_URL", GATEWAY)
    assert main(["policy", "show"]) == 0
    assert gateway == [cli.DEFAULT_GATEWAY, GATEWAY]


def test_reload_lists_what_changed(
    gateway: list[str], policy_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    policy_file.write_text(TIGHTER.replace("default: deny", "default: allow"), encoding="utf-8")
    assert main(["policy", "reload"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("reloaded ")
    assert "  rules added: reads" in out
    assert "  rules removed: tickets" in out
    assert "  rules changed: echo-for-all" in out
    assert "  rate limits changed: per-agent" in out
    assert "  budgets added: daily" in out
    assert "  default is now allow" in out
    assert main(["policy", "reload"]) == 0
    assert capsys.readouterr().out.startswith("unchanged: ")


def test_a_refused_reload_fails_and_show_reports_it(
    gateway: list[str], policy_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    policy_file.write_text("version: 1\nrules: [\n", encoding="utf-8")
    assert main(["policy", "reload"]) == 1
    assert "error: 422: policy is not valid YAML" in capsys.readouterr().err
    assert main(["policy", "show"]) == 0
    assert "last reload failed: policy is not valid YAML" in capsys.readouterr().out


def test_json_output(gateway: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["policy", "show", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["rule_ids"] == ["echo-for-all", "tickets"]
    assert main(["policy", "reload", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["changed"] is False


def test_a_wrong_token_is_reported(
    gateway: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("WARDEN_ADMIN_TOKEN", "x" * 20)
    assert main(["policy", "show"]) == 1
    assert "error: 401: invalid or missing admin token" in capsys.readouterr().err


def test_the_token_is_required(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("WARDEN_ADMIN_TOKEN", raising=False)
    assert main(["policy", "show"]) == 2
    assert "set WARDEN_ADMIN_TOKEN" in capsys.readouterr().err


def test_an_unreachable_gateway_is_reported(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refusing(base_url: str, token: str) -> httpx.Client:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        return httpx.Client(base_url=base_url, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(cli, "_admin_client", refusing)
    monkeypatch.setenv("WARDEN_ADMIN_TOKEN", ADMIN_TOKEN)
    assert main(["policy", "reload", "--gateway", GATEWAY]) == 1
    assert f"cannot reach the gateway at {GATEWAY}" in capsys.readouterr().err


def test_a_non_json_error_is_shown_as_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def proxy_error(base_url: str, token: str) -> httpx.Client:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(502, text="bad gateway")

        return httpx.Client(base_url=base_url, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(cli, "_admin_client", proxy_error)
    monkeypatch.setenv("WARDEN_ADMIN_TOKEN", ADMIN_TOKEN)
    assert main(["policy", "show"]) == 1
    assert "error: 502: bad gateway" in capsys.readouterr().err


def test_the_real_client_sends_the_token() -> None:
    with cli._admin_client(GATEWAY, ADMIN_TOKEN) as client:
        assert client.headers["authorization"] == f"Bearer {ADMIN_TOKEN}"
        assert str(client.base_url) == f"{GATEWAY}"
