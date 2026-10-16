"""Rate limits in the policy document and their matching."""

from __future__ import annotations

from typing import Any

import pytest

from mcp_warden.policy import LimitScope, Period, PolicyEngine, PolicyError, parse_policy


def policy(*limits: dict[str, Any]) -> dict[str, Any]:
    return {"version": 1, "rate_limits": list(limits)}


def test_defaults_and_derived_values() -> None:
    doc = parse_policy(policy({"id": "base", "requests": 60, "per": "minute"}))
    (limit,) = doc.rate_limits
    assert limit.scope is LimitScope.AGENT
    assert limit.agents == limit.servers == limit.tools == ["*"]
    assert limit.capacity == 60
    assert limit.refill_per_second == pytest.approx(1.0)


def test_burst_sets_the_bucket_size() -> None:
    doc = parse_policy(
        policy({"id": "w", "requests": 10, "per": "hour", "burst": 2, "scope": "tool"})
    )
    (limit,) = doc.rate_limits
    assert limit.capacity == 2
    assert limit.scope is LimitScope.TOOL
    assert limit.per is Period.HOUR
    assert limit.refill_per_second == pytest.approx(10 / 3600)


@pytest.mark.parametrize(
    ("limit", "message"),
    [
        ({"id": "x", "requests": 0, "per": "minute"}, "requests"),
        ({"id": "x", "requests": True, "per": "minute"}, "requests"),
        ({"id": "x", "requests": 1.5, "per": "minute"}, "requests"),
        ({"id": "x", "requests": 5, "per": "fortnight"}, "per"),
        ({"id": "x", "requests": 5}, "per"),
        ({"id": "x", "requests": 5, "per": "second", "burst": 0}, "burst"),
        ({"id": "x", "requests": 5, "per": "second", "scope": "server"}, "scope"),
        ({"id": "x", "requests": 5, "per": "second", "tools": []}, "tools"),
        ({"id": "x", "requests": 5, "per": "second", "window": 3}, "window"),
        ({"id": "bad id", "requests": 5, "per": "second"}, "id"),
    ],
)
def test_invalid_limits_are_rejected(limit: dict[str, Any], message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        parse_policy(policy(limit))


def test_duplicate_limit_ids_are_rejected() -> None:
    limit = {"id": "same", "requests": 1, "per": "second"}
    with pytest.raises(PolicyError, match="duplicate rate limit id"):
        parse_policy(policy(limit, limit))


def test_a_limit_may_share_an_id_with_a_rule() -> None:
    doc = parse_policy(
        {
            "version": 1,
            "rules": [{"id": "demo", "effect": "allow"}],
            "rate_limits": [{"id": "demo", "requests": 1, "per": "second"}],
        }
    )
    assert doc.rules[0].id == doc.rate_limits[0].id


def test_limits_match_by_agent_server_and_tool_in_document_order() -> None:
    engine = PolicyEngine(
        parse_policy(
            policy(
                {"id": "everyone", "requests": 100, "per": "minute"},
                {"id": "bots", "agents": ["bot-*"], "requests": 10, "per": "minute"},
                {
                    "id": "writes",
                    "servers": ["github"],
                    "tools": ["create_*"],
                    "requests": 1,
                    "per": "minute",
                },
            )
        )
    )
    ids = [lim.id for lim in engine.rate_limits_for("bot-1", "github", "create_issue")]
    assert ids == ["everyone", "bots", "writes"]
    assert [lim.id for lim in engine.rate_limits_for("alice", "github", "get_issue")] == [
        "everyone"
    ]


def test_example_policy_limits_are_valid() -> None:
    from gateway_helpers import EXAMPLE_POLICY
    from mcp_warden.policy import load_policy_file

    assert load_policy_file(EXAMPLE_POLICY).rate_limits
