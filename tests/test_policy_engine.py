from __future__ import annotations

import pytest

from mcp_warden.policy import Effect, Policy, PolicyEngine, Rule, ToolCallRequest


def engine_for(*rules: Rule, default: Effect = Effect.DENY) -> PolicyEngine:
    return PolicyEngine(Policy(version=1, default=default, rules=list(rules)))


def req(agent: str = "bot", server: str = "github", tool: str = "get_issue") -> ToolCallRequest:
    return ToolCallRequest(agent=agent, server=server, tool=tool)


def test_default_deny_when_nothing_matches() -> None:
    decision = engine_for().evaluate(req())
    assert decision.effect is Effect.DENY
    assert decision.rule_id is None
    assert not decision.allowed
    assert "default" in decision.reason


def test_default_allow_is_respected() -> None:
    decision = engine_for(default=Effect.ALLOW).evaluate(req())
    assert decision.allowed


def test_allow_rule_matches_on_all_three_dimensions() -> None:
    engine = engine_for(
        Rule(id="r1", effect=Effect.ALLOW, agents=["bot"], servers=["github"], tools=["get_*"])
    )
    assert engine.evaluate(req()).allowed
    assert not engine.evaluate(req(agent="other")).allowed
    assert not engine.evaluate(req(server="jira")).allowed
    assert not engine.evaluate(req(tool="create_issue")).allowed


@pytest.mark.parametrize("order", ["deny_first", "deny_last"])
def test_deny_overrides_allow_regardless_of_order(order: str) -> None:
    allow = Rule(id="allow-all", effect=Effect.ALLOW)
    deny = Rule(id="no-delete", effect=Effect.DENY, tools=["delete_*"])
    rules = [deny, allow] if order == "deny_first" else [allow, deny]
    decision = engine_for(*rules).evaluate(req(tool="delete_repo"))
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "no-delete"
    assert set(decision.matched_rule_ids) == {"allow-all", "no-delete"}


def test_require_approval_beats_allow_but_loses_to_deny() -> None:
    allow = Rule(id="allow", effect=Effect.ALLOW)
    approve = Rule(id="approve", effect=Effect.REQUIRE_APPROVAL, tools=["create_*", "delete_*"])
    deny = Rule(id="deny", effect=Effect.DENY, tools=["delete_*"])
    engine = engine_for(allow, approve, deny)
    assert engine.evaluate(req(tool="create_pr")).effect is Effect.REQUIRE_APPROVAL
    assert engine.evaluate(req(tool="delete_pr")).effect is Effect.DENY
    assert engine.evaluate(req(tool="get_pr")).effect is Effect.ALLOW


def test_first_rule_with_winning_effect_is_reported() -> None:
    engine = engine_for(
        Rule(id="first", effect=Effect.ALLOW, description="first allow"),
        Rule(id="second", effect=Effect.ALLOW),
    )
    decision = engine.evaluate(req())
    assert decision.rule_id == "first"
    assert decision.reason == "first allow"


def test_matching_is_case_sensitive() -> None:
    engine = engine_for(Rule(id="r", effect=Effect.ALLOW, tools=["get_*"]))
    assert not engine.evaluate(req(tool="GET_issue")).allowed


def test_glob_character_classes_and_single_char() -> None:
    engine = engine_for(Rule(id="r", effect=Effect.ALLOW, agents=["agent-[ab]?"]))
    assert engine.evaluate(req(agent="agent-a1")).allowed
    assert engine.evaluate(req(agent="agent-b9")).allowed
    assert not engine.evaluate(req(agent="agent-c1")).allowed
    assert not engine.evaluate(req(agent="agent-a12")).allowed


def test_pattern_must_match_whole_value() -> None:
    engine = engine_for(Rule(id="r", effect=Effect.ALLOW, tools=["get"]))
    assert not engine.evaluate(req(tool="get_issue")).allowed
    assert not engine.evaluate(req(tool="forget")).allowed


def test_visible_tools_hides_denied_but_keeps_approval_tools() -> None:
    engine = engine_for(
        Rule(id="read", effect=Effect.ALLOW, tools=["get_*"]),
        Rule(id="write", effect=Effect.REQUIRE_APPROVAL, tools=["create_*"]),
    )
    visible = engine.visible_tools("bot", "github", ["get_issue", "create_issue", "delete_repo"])
    assert visible == ["get_issue", "create_issue"]
