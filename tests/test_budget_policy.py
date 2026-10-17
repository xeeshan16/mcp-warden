"""The ``budgets`` section of the policy document."""

from __future__ import annotations

from typing import Any

import pytest

from mcp_warden.policy import (
    BudgetWindow,
    LimitScope,
    PolicyEngine,
    PolicyError,
    parse_policy,
)


def policy(*budgets: dict[str, Any]) -> dict[str, Any]:
    return {"version": 1, "budgets": list(budgets)}


def test_defaults_and_fields() -> None:
    parsed = parse_policy(policy({"id": "b", "window": "day", "max_calls": 10}))
    (budget,) = parsed.budgets
    assert budget.window is BudgetWindow.DAY
    assert budget.scope is LimitScope.AGENT
    assert (budget.agents, budget.servers, budget.tools) == (["*"], ["*"], ["*"])
    assert (budget.max_calls, budget.max_tokens) == (10, None)


def test_tokens_only_and_both() -> None:
    parsed = parse_policy(
        policy(
            {"id": "t", "window": "hour", "max_tokens": 500},
            {"id": "both", "window": "month", "max_calls": 1, "max_tokens": 2, "scope": "tool"},
        )
    )
    assert [b.id for b in parsed.budgets] == ["t", "both"]
    assert parsed.budgets[1].scope is LimitScope.TOOL


@pytest.mark.parametrize(
    ("budget", "message"),
    [
        ({"id": "b", "window": "day"}, "needs max_calls, max_tokens or both"),
        ({"id": "b", "window": "fortnight", "max_calls": 1}, "window"),
        ({"id": "b", "window": "day", "max_calls": 0}, "max_calls"),
        ({"id": "b", "window": "day", "max_calls": "10"}, "max_calls"),
        ({"id": "b", "window": "day", "max_calls": True}, "max_calls"),
        ({"id": "b", "window": "day", "max_tokens": 1.5}, "max_tokens"),
        ({"id": "b", "window": "day", "max_calls": 1, "max_call": 2}, "max_call"),
        ({"id": "b", "window": "day", "max_calls": 1, "tools": []}, "at least one pattern"),
        ({"id": "b c", "window": "day", "max_calls": 1}, "id"),
    ],
)
def test_invalid_budgets_are_rejected(budget: dict[str, Any], message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        parse_policy(policy(budget))


def test_duplicate_budget_ids_are_rejected() -> None:
    b = {"id": "same", "window": "day", "max_calls": 1}
    with pytest.raises(PolicyError, match="duplicate budget id: 'same'"):
        parse_policy(policy(b, b))


def test_budget_may_share_an_id_with_a_rate_limit() -> None:
    doc = policy({"id": "x", "window": "day", "max_calls": 1})
    doc["rate_limits"] = [{"id": "x", "requests": 1, "per": "second"}]
    assert parse_policy(doc).budgets[0].id == "x"


def test_budgets_for_matches_by_glob_in_document_order() -> None:
    engine = PolicyEngine(
        parse_policy(
            policy(
                {"id": "all", "window": "day", "max_calls": 100},
                {"id": "bot", "agents": ["bot-*"], "window": "day", "max_calls": 5},
                {
                    "id": "gh",
                    "servers": ["github"],
                    "tools": ["push_*"],
                    "window": "hour",
                    "max_calls": 1,
                },
            )
        )
    )
    assert [b.id for b in engine.budgets_for("bot-1", "github", "push_files")] == [
        "all",
        "bot",
        "gh",
    ]
    assert [b.id for b in engine.budgets_for("human", "github", "get_file")] == ["all"]
