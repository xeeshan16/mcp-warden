"""Policy evaluation.

Resolution is order-independent and deterministic: every rule that matches the
request is collected, and the most restrictive effect wins
(``deny`` > ``require_approval`` > ``allow``). Among rules with the winning
effect, the first one in document order is reported as the deciding rule. If no
rule matches, the policy's ``default`` effect applies.

Order independence matters for a security control: appending an ``allow`` rule
can never override an existing ``deny``, so policies stay safe to edit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import translate
from functools import lru_cache

from mcp_warden.policy.model import Effect, Policy, Rule


@dataclass(frozen=True, slots=True)
class ToolCallRequest:
    """The identity facts a policy decision is made on."""

    agent: str
    server: str
    tool: str


@dataclass(frozen=True, slots=True)
class Decision:
    """Result of evaluating a request against a policy."""

    effect: Effect
    rule_id: str | None
    reason: str
    matched_rule_ids: tuple[str, ...] = field(default_factory=tuple)

    @property
    def allowed(self) -> bool:
        return self.effect is Effect.ALLOW


@lru_cache(maxsize=4096)
def _compile(pattern: str) -> re.Pattern[str]:
    # fnmatch.translate is case-sensitive when used with re directly (unlike
    # fnmatch.fnmatch on case-insensitive filesystems), which is what we want.
    return re.compile(translate(pattern))


def _matches_any(value: str, patterns: list[str]) -> bool:
    return any(_compile(p).match(value) is not None for p in patterns)


def rule_matches(rule: Rule, request: ToolCallRequest) -> bool:
    return (
        _matches_any(request.agent, rule.agents)
        and _matches_any(request.server, rule.servers)
        and _matches_any(request.tool, rule.tools)
    )


class PolicyEngine:
    """Evaluates tool-call requests against an immutable policy."""

    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    @property
    def policy(self) -> Policy:
        return self._policy

    def evaluate(self, request: ToolCallRequest) -> Decision:
        matched = [rule for rule in self._policy.rules if rule_matches(rule, request)]
        if not matched:
            return Decision(
                effect=self._policy.default,
                rule_id=None,
                reason=f"no rule matched; default is {self._policy.default.value}",
            )

        winner = max(matched, key=lambda r: r.effect.precedence)
        # max() returns the first maximal element, i.e. first in document order.
        return Decision(
            effect=winner.effect,
            rule_id=winner.id,
            reason=winner.description or f"matched rule {winner.id!r}",
            matched_rule_ids=tuple(r.id for r in matched),
        )

    def visible_tools(self, agent: str, server: str, tools: list[str]) -> list[str]:
        """Filter a tool listing down to tools the agent could ever invoke.

        Tools that would be denied outright are hidden; tools that need approval
        stay visible so the agent can request them.
        """
        return [
            tool
            for tool in tools
            if self.evaluate(ToolCallRequest(agent, server, tool)).effect is not Effect.DENY
        ]
