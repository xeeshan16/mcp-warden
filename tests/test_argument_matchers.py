from __future__ import annotations

from typing import Any

import pytest

from mcp_warden.policy import (
    ArgumentMatcher,
    Effect,
    Policy,
    PolicyEngine,
    PolicyError,
    Rule,
    ToolCallRequest,
    load_policy,
)
from mcp_warden.policy.engine import json_equal, matcher_holds, resolve_path


def m(**kwargs: Any) -> ArgumentMatcher:
    return ArgumentMatcher.model_validate(kwargs)


ARGS: dict[str, Any] = {
    "env": "prod",
    "count": 3,
    "ratio": 0.5,
    "flag": True,
    "nothing": None,
    "options": {"mode": "fast", "tags": ["a", "b"]},
    "files": ["/srv/a.txt", "/etc/passwd"],
}


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("env", "prod"),
        ("options.mode", "fast"),
        ("options.tags.1", "b"),
        ("files.0", "/srv/a.txt"),
        ("nothing", None),
    ],
)
def test_resolve_path(path: str, expected: Any) -> None:
    assert resolve_path(ARGS, path) == expected


@pytest.mark.parametrize("path", ["missing", "env.length", "files.9", "files.x", "options.x.y"])
def test_unresolvable_paths_are_missing_not_null(path: str) -> None:
    assert not matcher_holds(m(path=path, equals=None), ARGS)
    assert matcher_holds(m(path=path, present=False), ARGS)


@pytest.mark.parametrize(
    ("left", "right", "equal"),
    [
        (1, 1.0, True),
        (1, True, False),
        (0, False, False),
        (True, True, True),
        ("1", 1, False),
        (None, None, True),
        (None, False, False),
    ],
)
def test_json_equal(left: Any, right: Any, equal: bool) -> None:
    assert json_equal(left, right) is equal


@pytest.mark.parametrize(
    ("matcher", "holds"),
    [
        (m(path="env", equals="prod"), True),
        (m(path="env", equals="dev"), False),
        (m(path="count", equals=3), True),
        (m(path="flag", equals=1), False),
        (m(path="nothing", equals=None), True),
        (m(path="env", one_of=["staging", "prod"]), True),
        (m(path="count", one_of=["3"]), False),
        (m(path="files.0", glob="/srv/*"), True),
        (m(path="files.1", glob="/srv/*"), False),
        (m(path="count", glob="*"), False),
        (m(path="options.mode", regex="fa|fast"), True),
        (m(path="options.mode", regex="fa"), False),
        (m(path="env", present=True), True),
        (m(path="env", max_length=4), True),
        (m(path="env", max_length=3), False),
        (m(path="files", max_length=2), True),
        (m(path="count", max_length=10), False),
        (m(path="count", min=1, max=3), True),
        (m(path="ratio", max=0.4), False),
        (m(path="ratio", min=0.5), True),
        (m(path="flag", min=0), False),
        (m(path="env", min=0), False),
    ],
)
def test_operators(matcher: ArgumentMatcher, holds: bool) -> None:
    assert matcher_holds(matcher, ARGS) is holds


def test_not_negates_including_missing_values() -> None:
    assert matcher_holds(m(path="env", equals="dev", **{"not": True}), ARGS)
    assert not matcher_holds(m(path="env", equals="prod", **{"not": True}), ARGS)
    # "env is not prod" also holds when there is no env at all.
    assert matcher_holds(m(path="env", equals="prod", **{"not": True}), {})


@pytest.mark.parametrize(
    ("matcher", "message"),
    [
        ("{path: x}", "needs one of"),
        ("{path: x, equals: 1, glob: a}", "use one operator"),
        ("{path: x, regex: '('}", "invalid regular expression"),
        ("{path: x, min: 3, max: 1}", "greater than max"),
        ("{path: x, one_of: []}", "at least 1"),
        ("{path: x, one_of: null}", "must not be null"),
        ("{path: x, max: null}", "must be numbers"),
        ("{path: x, max_length: -1}", "greater than or equal to 0"),
        ("{path: x, min: true}", "min"),
        ("{path: 'a..b', present: true}", "path"),
        ("{path: x, present: true, typo: 1}", "Extra inputs"),
    ],
)
def test_invalid_matchers_are_rejected(matcher: str, message: str) -> None:
    text = f"version: 1\nrules:\n  - id: r\n    effect: deny\n    arguments:\n      - {matcher}\n"
    with pytest.raises(PolicyError, match=message):
        load_policy(text)


def engine(*rules: Rule, default: Effect = Effect.DENY) -> PolicyEngine:
    return PolicyEngine(Policy(version=1, default=default, rules=list(rules)))


def call(tool: str, arguments: dict[str, Any] | None) -> ToolCallRequest:
    return ToolCallRequest("bot", "github", tool, arguments)


PROTECT_MAIN = Rule(
    id="protect-main",
    effect=Effect.DENY,
    tools=["push_*"],
    arguments=[m(path="branch", one_of=["main", "master"])],
)
ALLOW_PUSH = Rule(id="allow-push", effect=Effect.ALLOW, tools=["push_*"])


def test_conditional_deny_applies_only_when_arguments_match() -> None:
    e = engine(PROTECT_MAIN, ALLOW_PUSH)
    denied = e.evaluate(call("push_files", {"branch": "main"}))
    assert denied.effect is Effect.DENY
    assert denied.rule_id == "protect-main"
    assert e.evaluate(call("push_files", {"branch": "feature/x"})).allowed
    # A dry run without arguments sees an empty object.
    assert e.evaluate(call("push_files", None)).allowed


def test_all_matchers_of_a_rule_must_hold() -> None:
    rule = Rule(
        id="small-reads",
        effect=Effect.ALLOW,
        tools=["read_file"],
        arguments=[m(path="path", glob="/srv/data/*"), m(path="limit", max=100)],
    )
    e = engine(rule)
    assert e.evaluate(call("read_file", {"path": "/srv/data/x", "limit": 10})).allowed
    assert not e.evaluate(call("read_file", {"path": "/srv/data/x", "limit": 1000})).allowed
    assert not e.evaluate(call("read_file", {"path": "/srv/data/x"})).allowed


def test_conditional_deny_does_not_hide_a_tool() -> None:
    e = engine(PROTECT_MAIN, ALLOW_PUSH)
    assert e.visible_tools("bot", "github", ["push_files"]) == ["push_files"]


def test_unconditional_deny_hides_even_with_conditional_allow() -> None:
    e = engine(
        Rule(id="no", effect=Effect.DENY, tools=["drop_*"]),
        Rule(
            id="maybe", effect=Effect.ALLOW, tools=["drop_*"], arguments=[m(path="x", present=True)]
        ),
    )
    assert e.visible_tools("bot", "github", ["drop_table"]) == []


def test_conditional_allow_keeps_a_tool_visible() -> None:
    rule = Rule(
        id="maybe", effect=Effect.ALLOW, tools=["read_file"], arguments=[m(path="p", present=True)]
    )
    assert engine(rule).visible_tools("bot", "github", ["read_file", "other"]) == ["read_file"]


def test_only_conditional_denies_and_default_deny_hides() -> None:
    e = engine(PROTECT_MAIN)
    assert e.visible_tools("bot", "github", ["push_files"]) == []
    assert engine(PROTECT_MAIN, default=Effect.ALLOW).visible_tools(
        "bot", "github", ["push_files"]
    ) == ["push_files"]
