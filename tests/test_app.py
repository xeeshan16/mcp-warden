from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mcp_warden import __version__
from mcp_warden.app import create_app
from mcp_warden.config import AuthMode, Settings
from mcp_warden.policy import PolicyError

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "policy.yaml"


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(Settings(policy_path=EXAMPLE, auth_mode=AuthMode.TRUSTED_HEADER)))


def test_healthz(client: TestClient) -> None:
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "version": __version__}


def test_policy_summary(client: TestClient) -> None:
    body = client.get("/v1/policy").json()
    assert body["version"] == 1
    assert body["default"] == "deny"
    assert body["rule_count"] == 9
    assert "never-destructive" in body["rule_ids"]


@pytest.mark.parametrize(
    ("agent", "server", "tool", "effect", "rule_id"),
    [
        ("bot", "github", "get_issue", "allow", "read-only-everywhere"),
        ("bot", "github", "create_issue", "require_approval", "writes-need-a-human"),
        ("bot", "github", "delete_repo", "deny", "never-destructive"),
        ("bot", "db", "run_sql", "deny", None),
    ],
)
def test_evaluate(
    client: TestClient, agent: str, server: str, tool: str, effect: str, rule_id: str | None
) -> None:
    resp = client.post("/v1/policy/evaluate", json={"agent": agent, "server": server, "tool": tool})
    assert resp.status_code == 200
    body = resp.json()
    assert body["effect"] == effect
    assert body["rule_id"] == rule_id


@pytest.mark.parametrize(
    ("arguments", "effect", "rule_id"),
    [
        ({"branch": "main"}, "deny", "no-pushes-to-default-branch"),
        ({"branch": "feature/x"}, "require_approval", "writes-need-a-human"),
        (None, "require_approval", "writes-need-a-human"),
    ],
)
def test_evaluate_with_arguments(
    client: TestClient, arguments: dict[str, str] | None, effect: str, rule_id: str
) -> None:
    payload = {"agent": "bot", "server": "github", "tool": "push_files", "arguments": arguments}
    body = client.post("/v1/policy/evaluate", json=payload).json()
    assert (body["effect"], body["rule_id"]) == (effect, rule_id)


def test_evaluate_rejects_malformed_names(client: TestClient) -> None:
    resp = client.post(
        "/v1/policy/evaluate", json={"agent": "bot one", "server": "github", "tool": "x"}
    )
    assert resp.status_code == 422


def test_broken_policy_fails_at_startup(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\nrules:\n  - id: a\n    effect: nope\n", encoding="utf-8")
    with pytest.raises(PolicyError):
        create_app(Settings(policy_path=bad, auth_mode=AuthMode.TRUSTED_HEADER))
