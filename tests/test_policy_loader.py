from __future__ import annotations

from pathlib import Path

import pytest

from mcp_warden.policy import (
    Effect,
    PolicyEngine,
    PolicyError,
    ToolCallRequest,
    load_policy,
    load_policy_file,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "policy.yaml"


def test_example_policy_loads_and_behaves_as_documented() -> None:
    engine = PolicyEngine(load_policy_file(EXAMPLE))

    def effect(agent: str, server: str, tool: str) -> Effect:
        return engine.evaluate(ToolCallRequest(agent, server, tool)).effect

    assert effect("any", "github", "get_issue") is Effect.ALLOW
    assert effect("support-bot", "tickets", "create_ticket") is Effect.ALLOW
    assert effect("other-bot", "tickets", "create_ticket") is Effect.DENY
    assert effect("any", "github", "create_pull_request") is Effect.REQUIRE_APPROVAL
    assert effect("any", "github", "delete_repo") is Effect.DENY
    assert effect("any", "db", "run_sql") is Effect.DENY


def test_minimal_policy_defaults() -> None:
    policy = load_policy("version: 1\n")
    assert policy.default is Effect.DENY
    assert policy.rules == []


def test_rule_defaults_match_everything() -> None:
    policy = load_policy("version: 1\nrules:\n  - id: all\n    effect: allow\n")
    rule = policy.rules[0]
    assert rule.agents == ["*"] and rule.servers == ["*"] and rule.tools == ["*"]


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("- 1\n- 2\n", "mapping"),
        ("version: [", "not valid YAML"),
        ("version: 2\n", "version"),
        ("version: 1\ndefualt: allow\n", "defualt"),
        ("version: 1\nrules:\n  - id: a\n    effect: maybe\n", "effect"),
        (
            "version: 1\nrules:\n  - id: a\n    effect: allow\n  - id: a\n    effect: deny\n",
            "duplicate rule id",
        ),
        ("version: 1\nrules:\n  - id: a\n    effect: allow\n    tools: []\n", "at least one"),
        ("version: 1\nrules:\n  - id: a\n    effect: allow\n    tools: ['  ']\n", "blank"),
        ("version: 1\nrules:\n  - id: 'bad id'\n    effect: allow\n", "id"),
        ("version: 1\nrules:\n  - id: a\n    effect: allow\n    tool: ['x']\n", "tool"),
    ],
)
def test_invalid_policies_are_rejected_with_a_clear_message(text: str, fragment: str) -> None:
    with pytest.raises(PolicyError) as excinfo:
        load_policy(text)
    assert fragment in str(excinfo.value)


def test_oversized_policy_is_rejected() -> None:
    with pytest.raises(PolicyError, match="exceeds"):
        load_policy("#" * 1_000_001)


def test_missing_file_is_a_policy_error(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy_file(tmp_path / "nope.yaml")


def test_yaml_tags_cannot_construct_objects() -> None:
    with pytest.raises(PolicyError):
        load_policy("!!python/object/apply:os.system ['echo hi']\n")
