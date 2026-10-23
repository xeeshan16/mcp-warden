"""Policing prompts and resources: the policy model, the engine and the gateway."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from gateway_helpers import EXAMPLE_POLICY, initialize, make_client, rpc
from mcp_warden.app import create_app
from mcp_warden.audit import AuditQuery, Outcome
from mcp_warden.config import AuthMode, Settings
from mcp_warden.jsonrpc import ErrorCode
from mcp_warden.jsonrpc.mcp import is_valid_resource_uri
from mcp_warden.policy import (
    Effect,
    Policy,
    PolicyEngine,
    Rule,
    Target,
    ToolCallRequest,
    load_policy_file,
)
from mcp_warden.proxy import HttpUpstreamClient
from mcp_warden.upstreams import Upstream, UpstreamRegistry

# --- Policy model -------------------------------------------------------------


def test_a_rule_without_a_kind_is_a_tool_rule_for_every_tool() -> None:
    rule = Rule(id="r", effect=Effect.ALLOW)
    assert (rule.target, rule.names) == (Target.TOOL, ["*"])
    assert Rule(id="p", effect=Effect.ALLOW, prompts=["x"]).target is Target.PROMPT
    assert Rule(id="u", effect=Effect.DENY, resources=["a://*"]).names == ["a://*"]


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"tools": ["a"], "prompts": ["b"]}, "tools and prompts"),
        ({"prompts": ["a"], "resources": ["b://*"]}, "prompts and resources"),
        ({"resources": ["a://*"], "arguments": [{"path": "x", "present": True}]}, "no arguments"),
        ({"prompts": ["a"], "effect": "require_approval"}, "only available for tools"),
        ({"resources": []}, "at least one pattern"),
        ({"prompts": ["  "]}, "blank"),
    ],
)
def test_invalid_prompt_and_resource_rules(fields: dict[str, Any], message: str) -> None:
    data: dict[str, Any] = {"id": "r", "effect": "allow", **fields}
    with pytest.raises(ValidationError, match=message):
        Rule.model_validate(data)


def test_prompt_rules_may_match_arguments() -> None:
    rule = Rule.model_validate(
        {
            "id": "r",
            "effect": "deny",
            "prompts": ["p"],
            "arguments": [{"path": "lang", "equals": "xx"}],
        }
    )
    assert rule.conditional


# --- Engine --------------------------------------------------------------------


def _engine(*rules: dict[str, Any], default: Effect = Effect.DENY) -> PolicyEngine:
    return PolicyEngine(
        Policy(version=1, default=default, rules=[Rule.model_validate(r) for r in rules])
    )


def test_rules_only_match_their_own_kind() -> None:
    engine = _engine(
        {"id": "tool-x", "effect": "allow", "tools": ["x"]},
        {"id": "prompt-x", "effect": "deny", "prompts": ["x"]},
    )
    tool = engine.evaluate(ToolCallRequest("a", "s", "x"))
    prompt = engine.evaluate(ToolCallRequest("a", "s", "x", target=Target.PROMPT))
    resource = engine.evaluate(ToolCallRequest("a", "s", "x", target=Target.RESOURCE))
    assert (tool.effect, tool.rule_id) == (Effect.ALLOW, "tool-x")
    assert (prompt.effect, prompt.rule_id) == (Effect.DENY, "prompt-x")
    assert (resource.effect, resource.rule_id) == (Effect.DENY, None)


def test_a_wildcard_tool_rule_never_allows_prompts_or_resources() -> None:
    engine = _engine({"id": "everything", "effect": "allow"})
    for target in (Target.PROMPT, Target.RESOURCE):
        decision = engine.evaluate(ToolCallRequest("a", "s", "x", target=target))
        assert decision.effect is Effect.DENY and decision.rule_id is None


def test_default_allow_covers_prompts_and_resources() -> None:
    engine = _engine(
        {"id": "no-secrets", "effect": "deny", "resources": ["file:///etc/*"]}, default=Effect.ALLOW
    )
    readme = ToolCallRequest("a", "s", "file:///srv/readme", target=Target.RESOURCE)
    shadow = ToolCallRequest("a", "s", "file:///etc/shadow", target=Target.RESOURCE)
    assert engine.evaluate(readme).effect is Effect.ALLOW
    assert engine.evaluate(shadow).rule_id == "no-secrets"


def test_uri_globs_cross_slashes() -> None:
    engine = _engine({"id": "docs", "effect": "allow", "resources": ["demo://docs/*"]})
    deep = ToolCallRequest("a", "s", "demo://docs/a/b/c", target=Target.RESOURCE)
    assert engine.evaluate(deep).effect is Effect.ALLOW


def test_always_denied_per_kind() -> None:
    engine = _engine(
        {"id": "p", "effect": "allow", "prompts": ["visible"]},
        {
            "id": "c",
            "effect": "deny",
            "prompts": ["visible"],
            "arguments": [{"path": "x", "present": True}],
        },
    )
    assert not engine.always_denied("a", "s", "visible", Target.PROMPT)
    assert engine.always_denied("a", "s", "hidden", Target.PROMPT)
    assert engine.always_denied("a", "s", "visible")  # no tool rule at all


def test_limits_and_budgets_never_apply_to_prompts() -> None:
    policy = Policy.model_validate(
        {
            "version": 1,
            "rate_limits": [{"id": "l", "requests": 1, "per": "minute"}],
            "budgets": [{"id": "b", "window": "day", "max_calls": 1}],
        }
    )
    engine = PolicyEngine(policy)
    assert [r.id for r in engine.rate_limits_for("a", "s", "t")] == ["l"]
    assert [b.id for b in engine.budgets_for("a", "s", "t")] == ["b"]


# --- URIs ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("uri", "valid"),
    [
        ("demo://docs/readme", True),
        ("file:///srv/docs/report.v1..2.txt", True),
        ("https://example.com/a?b=c#d", True),
        ("file:///srv/docs/../secrets", False),
        ("file:///srv/docs/./x", False),
        ("demo://docs/..", False),
        ("demo://docs/%2e%2e/internal/x", False),
        ("demo://docs%2Finternal", False),
        ("demo://docs/%5Cx", False),
        ("demo://docs\\..\\internal", False),
        ("DEMO://internal/salaries", False),
        ("demo://docs/a b", False),
        ("demo://docs/\x00", False),
        ("no-scheme", False),
        ("demo://" + "a" * 2050, False),
    ],
)
def test_resource_uris(uri: str, valid: bool) -> None:
    assert is_valid_resource_uri(uri) is valid


# --- Gateway, with the example policy -------------------------------------------


@pytest.fixture(params=[False, True], ids=["json", "sse"])
def client(request: pytest.FixtureRequest) -> Iterator[TestClient]:
    engine = PolicyEngine(load_policy_file(EXAMPLE_POLICY))
    with make_client(sse=request.param, engine=engine) as c:
        yield c


def send(client: TestClient, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    headers = initialize(client)
    resp = client.post("/mcp/demo", json=rpc("r", method, params), headers=headers)
    assert resp.status_code == 200
    body: dict[str, Any] = resp.json()
    assert body["id"] == "r"
    return body


def test_prompt_listing_keeps_conditionally_denied_prompts(client: TestClient) -> None:
    body = send(client, "prompts/list")
    assert [p["name"] for p in body["result"]["prompts"]] == ["summarize", "incident_report"]


def test_resource_listing_hides_denied_documents(client: TestClient) -> None:
    body = send(client, "resources/list")
    assert [r["uri"] for r in body["result"]["resources"]] == [
        "demo://docs/readme",
        "demo://docs/runbook",
    ]


def test_allowed_prompt_is_forwarded(client: TestClient) -> None:
    body = send(client, "prompts/get", {"name": "summarize", "arguments": {"text": "hello"}})
    text = body["result"]["messages"][0]["content"]["text"]
    assert text == "Summarize in one sentence: hello"


@pytest.mark.parametrize(("severity", "allowed"), [("high", True), ("sev0", False)])
def test_prompt_arguments_decide(client: TestClient, severity: str, allowed: bool) -> None:
    body = send(
        client, "prompts/get", {"name": "incident_report", "arguments": {"severity": severity}}
    )
    if allowed:
        assert "result" in body
    else:
        assert body["error"]["code"] == ErrorCode.POLICY_DENIED
        assert body["error"]["data"] == {
            "server": "demo",
            "prompt": "incident_report",
            "effect": "deny",
            "rule_id": "known-severities-only",
            "reason": "Incident reports are drafted for a known severity only.",
        }


def test_unknown_prompt_falls_to_the_default(client: TestClient) -> None:
    body = send(client, "prompts/get", {"name": "exfiltrate"})
    assert body["error"]["code"] == ErrorCode.POLICY_DENIED
    assert body["error"]["data"]["rule_id"] is None
    assert body["error"]["message"] == "prompt denied by policy: exfiltrate"


def test_allowed_resource_is_read(client: TestClient) -> None:
    body = send(client, "resources/read", {"uri": "demo://docs/readme"})
    assert body["result"]["contents"][0]["text"] == "The demo server answers deterministically."


@pytest.mark.parametrize("method", ["resources/read", "resources/subscribe"])
def test_denied_resource(client: TestClient, method: str) -> None:
    body = send(client, method, {"uri": "demo://internal/salaries"})
    assert body["error"]["code"] == ErrorCode.POLICY_DENIED
    assert body["error"]["data"]["uri"] == "demo://internal/salaries"
    assert body["error"]["data"]["rule_id"] == "no-internal-documents"


@pytest.mark.parametrize(
    "uri",
    [
        "demo://docs/../internal/salaries",
        "demo://docs/%2e%2e/internal/salaries",
        "DEMO://internal/salaries",
        "demo://docs\\..\\internal\\salaries",
    ],
)
def test_ambiguous_uris_are_refused_before_the_policy(client: TestClient, uri: str) -> None:
    body = send(client, "resources/read", {"uri": uri})
    assert body["error"]["code"] == ErrorCode.INVALID_PARAMS


def test_unsubscribe_is_never_denied(client: TestClient) -> None:
    assert (
        send(client, "resources/unsubscribe", {"uri": "demo://internal/salaries"})["result"] == {}
    )
    bad = send(client, "resources/unsubscribe", {"uri": "demo://docs/../x"})
    assert bad["error"]["code"] == ErrorCode.INVALID_PARAMS


def test_templates_are_forwarded(client: TestClient) -> None:
    body = send(client, "resources/templates/list")
    assert body["result"]["resourceTemplates"][0]["uriTemplate"] == "demo://docs/{name}"


def test_completions_for_hidden_prompts_are_refused(client: TestClient) -> None:
    argument = {"name": "severity", "value": "c"}
    visible = send(
        client,
        "completion/complete",
        {"ref": {"type": "ref/prompt", "name": "incident_report"}, "argument": argument},
    )
    assert visible["result"]["completion"]["values"] == ["critical"]
    hidden = send(
        client,
        "completion/complete",
        {"ref": {"type": "ref/prompt", "name": "secret_prompt"}, "argument": argument},
    )
    assert hidden["error"]["code"] == ErrorCode.POLICY_DENIED
    resource = send(
        client,
        "completion/complete",
        {"ref": {"type": "ref/resource", "uri": "demo://docs/{name}"}, "argument": argument},
    )
    assert "result" in resource


def test_malformed_params_are_invalid(client: TestClient) -> None:
    assert send(client, "prompts/get", {})["error"]["code"] == ErrorCode.INVALID_PARAMS
    assert (
        send(client, "prompts/get", {"name": "a\nb"})["error"]["code"] == ErrorCode.INVALID_PARAMS
    )
    assert send(client, "resources/read", {"uri": 7})["error"]["code"] == ErrorCode.INVALID_PARAMS
    assert send(client, "completion/complete", {})["error"]["code"] == ErrorCode.INVALID_PARAMS


def test_decisions_are_audited() -> None:
    engine = PolicyEngine(load_policy_file(EXAMPLE_POLICY))
    with make_client(engine=engine) as c:
        headers = initialize(c)
        for i, uri in enumerate(["demo://docs/readme", "demo://internal/salaries"]):
            c.post("/mcp/demo", json=rpc(i, "resources/read", {"uri": uri}), headers=headers)
        store = c.app.state.audit_store  # type: ignore[attr-defined]
        found = store.query(AuditQuery(method="resources/read")).events
    by_outcome = {e.outcome: e for e in found}
    allowed = by_outcome[Outcome.FORWARDED]
    assert (allowed.rule_id, allowed.effect) == ("demo-docs", "allow")
    denied = by_outcome[Outcome.DENIED]
    assert (denied.rule_id, denied.effect, denied.tool) == ("no-internal-documents", "deny", None)


def _gateway_replying(result: Any) -> TestClient:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": result})

    transport = HttpUpstreamClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    registry = UpstreamRegistry([Upstream("demo", "http://upstream.test/mcp", 2.0, 1.0, {})])
    app = create_app(
        Settings(
            policy_path=EXAMPLE_POLICY, upstreams_path=None, auth_mode=AuthMode.TRUSTED_HEADER
        ),
        upstreams=registry,
        transport=transport,
    )
    return TestClient(app)


@pytest.mark.parametrize(
    ("method", "result"),
    [
        ("prompts/list", {"prompts": [{"description": "no name"}]}),
        ("prompts/list", {"prompts": "summarize"}),
        ("resources/list", {"resources": [{"name": "no uri"}]}),
        ("resources/list", {}),
    ],
)
def test_unreadable_listings_fail_closed(method: str, result: Any) -> None:
    with _gateway_replying(result) as c:
        body = c.post("/mcp/demo", json=rpc(1, method)).json()
    assert body["error"]["code"] == ErrorCode.UPSTREAM_ERROR
    assert body["error"]["message"] == f"upstream returned an invalid {method} result"


def test_odd_listed_uris_are_hidden_and_extras_kept() -> None:
    result = {
        "resources": [
            {"uri": "demo://docs/a", "name": "a", "size": 3},
            {"uri": "demo://docs/../internal/b", "name": "b"},
            {"uri": "DEMO://docs/c", "name": "c"},
        ],
        "nextCursor": "2",
    }
    with _gateway_replying(result) as c:
        body = c.post("/mcp/demo", json=rpc(1, "resources/list")).json()
    assert body["result"] == {"resources": [result["resources"][0]], "nextCursor": "2"}


def test_dry_run_endpoint_and_cli_know_the_target(capsys: pytest.CaptureFixture[str]) -> None:
    from mcp_warden.__main__ import main

    token = "admin-token-for-tests-only"  # noqa: S105 - test fixture, not a secret
    with make_client(engine=PolicyEngine(load_policy_file(EXAMPLE_POLICY)), admin_token=token) as c:
        resp = c.post(
            "/v1/policy/evaluate",
            json={
                "agent": "bot",
                "server": "demo",
                "tool": "demo://internal/salaries",
                "target": "resource",
            },
            headers={"authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 200
    assert resp.json()["rule_id"] == "no-internal-documents"

    args = ["check", str(EXAMPLE_POLICY), "--agent", "bot", "--server", "demo"]
    assert main([*args, "--prompt", "summarize"]) == 0
    assert main([*args, "--resource", "demo://docs/readme"]) == 0
    out = capsys.readouterr().out
    assert "allow: bot -> demo prompt summarize (rule demo-prompts" in out
    assert "allow: bot -> demo resource demo://docs/readme (rule demo-docs" in out
    assert "rate limit per-agent" not in out and "budget " not in out
