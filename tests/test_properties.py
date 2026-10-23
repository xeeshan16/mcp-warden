"""Property-based tests: the parser, the policy engine and the gateway under fuzzed input.

These state the invariants the rest of the suite checks by example:

* the parser only ever fails with a JSON-RPC error, whatever bytes arrive,
  and what it accepts it re-serialises unchanged;
* policy decisions do not depend on rule order, never get weaker when a
  rule is added, and a tool hidden from a listing is denied for every
  possible set of arguments;
* the gateway never answers with a server error and never forwards a call
  the policy denies, however the request is shaped.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from hypothesis import HealthCheck, assume, event, given, settings
from hypothesis import strategies as st

from gateway_helpers import EXAMPLE_POLICY, INIT
from mcp_warden.app import create_app
from mcp_warden.config import AuthMode, Settings
from mcp_warden.fake_upstream import create_fake_upstream
from mcp_warden.jsonrpc import (
    ErrorCode,
    InvalidMessage,
    JsonRpcError,
    JsonRpcRequest,
    ParseLimits,
    parse_payload,
    to_wire,
)
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

FUZZ = settings(max_examples=200, deadline=None)

json_scalars = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**63), max_value=2**63)
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(max_size=20)
)
json_values = st.recursive(
    json_scalars,
    lambda inner: (
        st.lists(inner, max_size=5) | st.dictionaries(st.text(max_size=8), inner, max_size=5)
    ),
    max_leaves=25,
)
json_objects = st.dictionaries(st.text(max_size=8), json_values, max_size=6)

# --- Parser -----------------------------------------------------------------------


@FUZZ
@given(st.binary(max_size=2000))
def test_arbitrary_bytes_only_fail_as_json_rpc_errors(payload: bytes) -> None:
    try:
        result = parse_payload(payload)
    except JsonRpcError as exc:
        assert exc.code in (ErrorCode.PARSE_ERROR, ErrorCode.INVALID_REQUEST)
        return
    assert result.items


@FUZZ
@given(json_values)
def test_any_json_value_parses_or_fails_cleanly(value: Any) -> None:
    try:
        result = parse_payload(json.dumps(value))
    except JsonRpcError as exc:
        assert exc.code in (ErrorCode.PARSE_ERROR, ErrorCode.INVALID_REQUEST)
        return
    for item in result.items:
        if isinstance(item, InvalidMessage):
            assert item.error.error.code == ErrorCode.INVALID_REQUEST


message_objects = st.fixed_dictionaries(
    {},
    optional={
        "jsonrpc": st.sampled_from(["2.0", "1.0", 2.0]),
        "id": st.integers() | st.text(max_size=5) | st.none() | st.booleans(),
        "method": st.text(max_size=12) | st.integers(),
        "params": json_objects | st.lists(json_values, max_size=3) | json_scalars,
        "result": json_values,
        "error": json_objects,
        "extra": json_values,
    },
)


@FUZZ
@given(message_objects)
def test_message_shaped_objects_are_classified(obj: dict[str, Any]) -> None:
    (item,) = parse_payload(json.dumps(obj)).items
    event(type(item).__name__)
    if isinstance(item, InvalidMessage):
        return
    # Whatever was accepted is reproduced exactly: no member added or dropped.
    assert to_wire(item) == obj


requests = st.fixed_dictionaries(
    {
        "jsonrpc": st.just("2.0"),
        "id": st.integers(min_value=-(2**53), max_value=2**53) | st.text(max_size=20),
        "method": st.text(min_size=1, max_size=30),
    },
    optional={"params": json_objects},
)


@FUZZ
@given(requests)
def test_valid_requests_round_trip(message: dict[str, Any]) -> None:
    (item,) = parse_payload(json.dumps(message)).items
    assert isinstance(item, JsonRpcRequest)
    assert to_wire(item) == message


@FUZZ
@given(st.integers(min_value=1, max_value=40), st.integers(min_value=1, max_value=40))
def test_nesting_limit(depth: int, limit: int) -> None:
    payload = '{"jsonrpc":"2.0","id":1,"method":"m","params":' + '{"a":' * depth + "1"
    payload += "}" * depth + "}"
    limits = ParseLimits(max_depth=limit)
    if depth + 1 > limit:
        with pytest.raises(JsonRpcError) as caught:
            parse_payload(payload, limits)
        assert caught.value.code == ErrorCode.PARSE_ERROR
    else:
        assert parse_payload(payload, limits).items


@FUZZ
@given(st.integers(min_value=1, max_value=12), st.integers(min_value=1, max_value=12))
def test_batch_size_limit(size: int, limit: int) -> None:
    batch = json.dumps([{"jsonrpc": "2.0", "id": i, "method": "ping"} for i in range(size)])
    limits = ParseLimits(max_batch_size=limit)
    if size > limit:
        with pytest.raises(JsonRpcError, match="batch too large"):
            parse_payload(batch, limits)
    else:
        assert len(parse_payload(batch, limits).items) == size


# --- Policy engine --------------------------------------------------------------

NAMES = ["a", "b", "c"]
patterns = st.lists(st.sampled_from(["*", "a", "b", "c", "[ab]", "?"]), min_size=1, max_size=2)
matchers = st.lists(
    st.sampled_from(
        [
            {"path": "x", "equals": 1},
            {"path": "x", "min": 0, "max": 5},
            {"path": "y", "present": True},
            {"path": "y", "glob": "a*", "not": True},
        ]
    ),
    max_size=2,
)


@st.composite
def rules(draw: st.DrawFn, rule_id: str) -> Rule:
    target = draw(st.sampled_from(["tools", "prompts", "resources"]))
    effects = ["allow", "deny"] + (["require_approval"] if target == "tools" else [])
    data: dict[str, Any] = {
        "id": rule_id,
        "effect": draw(st.sampled_from(effects)),
        "agents": draw(patterns),
        "servers": draw(patterns),
        target: draw(patterns),
    }
    if target != "resources":
        data["arguments"] = draw(matchers)
    return Rule.model_validate(data)


@st.composite
def policies(draw: st.DrawFn) -> Policy:
    count = draw(st.integers(min_value=0, max_value=6))
    return Policy(
        version=1,
        default=draw(st.sampled_from(list(Effect))),
        rules=[draw(rules(f"r{i}")) for i in range(count)],
    )


arguments = st.fixed_dictionaries(
    {},
    optional={
        "x": st.integers(min_value=-2, max_value=8) | st.text(max_size=2) | st.none(),
        "y": st.text(max_size=3) | st.booleans(),
    },
)
call_requests = st.builds(
    ToolCallRequest,
    agent=st.sampled_from(NAMES),
    server=st.sampled_from(NAMES),
    tool=st.sampled_from(NAMES),
    arguments=arguments,
    target=st.sampled_from(list(Target)),
)


@FUZZ
@given(policies(), call_requests, st.randoms(use_true_random=False))
def test_rule_order_never_changes_the_effect(
    policy: Policy, request: ToolCallRequest, rng: Any
) -> None:
    shuffled = list(policy.rules)
    rng.shuffle(shuffled)
    reordered = Policy(version=1, default=policy.default, rules=shuffled)
    before = PolicyEngine(policy).evaluate(request)
    after = PolicyEngine(reordered).evaluate(request)
    assert before.effect is after.effect
    assert set(before.matched_rule_ids) == set(after.matched_rule_ids)


@FUZZ
@given(policies(), rules("added"), call_requests)
def test_a_matching_rule_never_weakens_a_rule_decision(
    policy: Policy, rule: Rule, request: ToolCallRequest
) -> None:
    before = PolicyEngine(policy).evaluate(request)
    after = PolicyEngine(
        Policy(version=1, default=policy.default, rules=[*policy.rules, rule])
    ).evaluate(request)
    if before.rule_id is not None:
        # A decision some rule made can only get stricter, never looser.
        assert after.effect.precedence >= before.effect.precedence
    if "added" not in after.matched_rule_ids:
        assert after.effect is before.effect


@FUZZ
@given(policies(), call_requests)
def test_hidden_means_denied_for_every_argument(policy: Policy, request: ToolCallRequest) -> None:
    engine = PolicyEngine(policy)
    hidden = engine.always_denied(request.agent, request.server, request.tool, request.target)
    if hidden:
        assert engine.evaluate(request).effect is Effect.DENY


@FUZZ
@given(policies(), call_requests)
def test_rules_only_decide_their_own_kind(policy: Policy, request: ToolCallRequest) -> None:
    decision = PolicyEngine(policy).evaluate(request)
    targets = {rule.id: rule.target for rule in policy.rules}
    assert all(targets[rule_id] is request.target for rule_id in decision.matched_rule_ids)


# --- The gateway -------------------------------------------------------------------


class _Recorder(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.bodies: list[Any] = []
        self._inner = httpx.ASGITransport(app=create_fake_upstream(require_session=False))

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.bodies.append(json.loads(request.content))
        return await self._inner.handle_async_request(request)


@pytest.fixture(scope="module")
def gateway() -> Iterator[tuple[TestClient, _Recorder]]:
    recorder = _Recorder()
    app = create_app(
        Settings(
            policy_path=EXAMPLE_POLICY, upstreams_path=None, auth_mode=AuthMode.TRUSTED_HEADER
        ),
        # The example policy's rules without its rate limits and budgets, which
        # would otherwise refuse most calls after the first few hundred examples.
        engine=PolicyEngine(
            load_policy_file(EXAMPLE_POLICY).model_copy(update={"rate_limits": [], "budgets": []})
        ),
        upstreams=UpstreamRegistry([Upstream("demo", "http://upstream.test/mcp", 2.0, 1.0, {})]),
        transport=HttpUpstreamClient(httpx.AsyncClient(transport=recorder)),
    )
    with TestClient(app) as client:
        yield client, recorder


DENIED_TOOLS = ["delete_records", "drop_table", "purge_cache", "x_delete"]
methods = st.sampled_from(
    [
        "tools/call",
        "tools/list",
        "prompts/get",
        "resources/read",
        "resources/subscribe",
        "completion/complete",
        "ping",
        "initialize",
    ]
)
call_params = st.fixed_dictionaries(
    {"name": st.sampled_from([*DENIED_TOOLS, "echo", "sleep", "", "a b"]) | st.text(max_size=8)},
    optional={"arguments": json_objects | json_scalars},
)
generic_messages = st.fixed_dictionaries(
    {"jsonrpc": st.just("2.0"), "id": st.integers(0, 10), "method": methods},
    optional={"params": call_params | json_objects | st.lists(json_values, max_size=2)},
)
# Calls shaped like the policy's interesting cases, so that denials and
# argument matchers are exercised and not only parse failures.
tool_calls = st.fixed_dictionaries(
    {
        "jsonrpc": st.just("2.0"),
        "id": st.integers(0, 10),
        "method": st.just("tools/call"),
        "params": st.fixed_dictionaries(
            {
                "name": st.sampled_from(
                    [*DENIED_TOOLS, "echo", "add", "get_forecast", "sleep", "create_ticket"]
                )
            },
            optional={
                "arguments": st.fixed_dictionaries(
                    {},
                    optional={
                        "seconds": st.sampled_from([0, 1.5, 2, 2.01, 3, -1, "1", None, True]),
                        "text": st.text(max_size=5),
                        "title": st.text(max_size=5),
                        "priority": st.sampled_from(["low", "urgent"]),
                    },
                )
            },
        ),
    }
)
resource_reads = st.fixed_dictionaries(
    {
        "jsonrpc": st.just("2.0"),
        "id": st.integers(0, 10),
        "method": st.sampled_from(["resources/read", "resources/subscribe"]),
        "params": st.fixed_dictionaries(
            {
                "uri": st.sampled_from(
                    [
                        "demo://docs/readme",
                        "demo://internal/salaries",
                        "demo://docs/../internal/salaries",
                        "demo://docs/%2e%2e/internal/salaries",
                        "Demo://internal/salaries",
                    ]
                )
            }
        ),
    }
)
fuzzed_messages = tool_calls | resource_reads | generic_messages
fuzzed_bodies = (
    fuzzed_messages.map(json.dumps)
    | st.lists(fuzzed_messages, min_size=1, max_size=4).map(json.dumps)
    | json_values.map(json.dumps)
    | st.text(max_size=50)
)
headers = st.fixed_dictionaries(
    {},
    optional={
        "x-warden-agent": st.sampled_from(["support-bot", "other-bot", "bad id!"]),
        "mcp-protocol-version": st.sampled_from(["2025-03-26", "2025-11-25", "2025-03-26", "0"]),
        "mcp-session-id": st.sampled_from(["s-1", "s-2", "bad id"]),
    },
)


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(body=fuzzed_bodies, extra=headers)
def test_gateway_never_errors_and_never_forwards_denied_calls(
    gateway: tuple[TestClient, _Recorder], body: str, extra: dict[str, str]
) -> None:
    client, recorder = gateway
    assume(all(v.isascii() for v in extra.values()))
    recorder.bodies.clear()
    try:
        resp = client.post(
            "/mcp/demo",
            content=body.encode(),
            headers={"content-type": "application/json", **extra},
        )
    except httpx.InvalidURL:  # pragma: no cover - header values httpx refuses to send
        return
    assert resp.status_code < 500, resp.text
    event(f"HTTP {resp.status_code}")
    for forwarded in recorder.bodies:
        event(f"forwarded {forwarded.get('method')}")
        if forwarded.get("method") == "tools/call":
            name = forwarded["params"]["name"]
            assert name not in DENIED_TOOLS
            if name == "sleep":
                seconds = forwarded["params"].get("arguments", {}).get("seconds")
                assert isinstance(seconds, int | float) and 0 <= seconds <= 2
        if forwarded.get("method") == "resources/read":
            assert forwarded["params"]["uri"].startswith("demo://docs/")


def test_the_fuzzed_gateway_does_forward_allowed_calls(
    gateway: tuple[TestClient, _Recorder],
) -> None:
    # Guards the property above against passing vacuously.
    client, recorder = gateway
    recorder.bodies.clear()
    client.post("/mcp/demo", json=INIT)
    call = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "echo", "arguments": {"text": "hi"}},
    }
    assert client.post("/mcp/demo", json=call).json()["result"]["content"][0]["text"] == "hi"
    assert [b["method"] for b in recorder.bodies] == ["initialize", "tools/call"]
