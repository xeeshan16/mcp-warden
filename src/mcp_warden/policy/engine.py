"""Policy evaluation.

Resolution is order-independent and deterministic: every rule that matches the
request is collected, and the most restrictive effect wins
(``deny`` > ``require_approval`` > ``allow``). Among rules with the winning
effect, the first one in document order is reported as the deciding rule. If no
rule matches, the policy's ``default`` effect applies.

Order independence matters for a security control: appending an ``allow`` rule
can never override an existing ``deny``, so policies stay safe to edit.

Argument matchers are evaluated against the ``tools/call`` arguments. They are
pure functions of the policy and the arguments: no I/O, no clock, so a decision
can always be replayed from an audit record.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from fnmatch import translate
from functools import lru_cache
from typing import Any

from mcp_warden.policy.model import ArgumentMatcher, Budget, Effect, Policy, RateLimit, Rule


@dataclass(frozen=True, slots=True)
class ToolCallRequest:
    """The facts a policy decision is made on.

    ``arguments`` is the ``tools/call`` arguments object. ``None`` means the
    arguments are not known (a dry run); conditional rules then see an empty
    object.
    """

    agent: str
    server: str
    tool: str
    arguments: Mapping[str, Any] | None = None


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


@lru_cache(maxsize=1024)
def _compile_regex(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


class _Missing:
    """Marks a path that does not resolve (distinct from a JSON ``null``)."""


_MISSING = _Missing()


def resolve_path(arguments: Mapping[str, Any], path: str) -> Any:
    """Follow a dotted path through objects (and lists, for numeric segments)."""
    value: Any = arguments
    for segment in path.split("."):
        if isinstance(value, Mapping):
            if segment not in value:
                return _MISSING
            value = value[segment]
        elif isinstance(value, list) and segment.isdigit():
            index = int(segment)
            if index >= len(value):
                return _MISSING
            value = value[index]
        else:
            return _MISSING
    return value


def _is_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def json_equal(left: Any, right: Any) -> bool:
    """Equality with JSON types: ``1 == 1.0`` but ``1 != true`` and ``0 != false``."""
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left is right
    if _is_number(left) and _is_number(right):
        return bool(left == right)
    return type(left) is type(right) and bool(left == right)


def _operator_holds(matcher: ArgumentMatcher, value: Any) -> bool:
    ops = matcher.operators
    if "present" in ops:
        return (value is not _MISSING) is matcher.present
    if value is _MISSING:
        return False
    if "equals" in ops:
        return json_equal(value, matcher.equals)
    if "one_of" in ops:
        return any(json_equal(value, option) for option in matcher.one_of or ())
    if "glob" in ops:
        return isinstance(value, str) and _compile(matcher.glob or "").match(value) is not None
    if "regex" in ops:
        pattern = _compile_regex(matcher.regex or "")
        return isinstance(value, str) and pattern.fullmatch(value) is not None
    if "max_length" in ops:
        return isinstance(value, str | list | dict) and len(value) <= (matcher.max_length or 0)
    # min and/or max.
    if not _is_number(value):
        return False
    if matcher.min is not None and value < matcher.min:
        return False
    return not (matcher.max is not None and value > matcher.max)


def matcher_holds(matcher: ArgumentMatcher, arguments: Mapping[str, Any]) -> bool:
    result = _operator_holds(matcher, resolve_path(arguments, matcher.path))
    return result is not matcher.negate


def _identity_matches(rule: Rule | RateLimit | Budget, request: ToolCallRequest) -> bool:
    return (
        _matches_any(request.agent, rule.agents)
        and _matches_any(request.server, rule.servers)
        and _matches_any(request.tool, rule.tools)
    )


def rule_matches(rule: Rule, request: ToolCallRequest) -> bool:
    if not _identity_matches(rule, request):
        return False
    arguments = request.arguments or {}
    return all(matcher_holds(m, arguments) for m in rule.arguments)


def _always_denied(policy: Policy, agent: str, server: str, tool: str) -> bool:
    probe = ToolCallRequest(agent, server, tool)
    candidates = [r for r in policy.rules if _identity_matches(r, probe)]
    if any(r.effect is Effect.DENY and not r.conditional for r in candidates):
        return True
    if any(r.effect is not Effect.DENY for r in candidates):
        return False
    return policy.default is Effect.DENY


class PolicyEngine:
    """Evaluates tool-call requests against the current policy.

    Policies are immutable; a reload swaps in a new one with :meth:`replace`.
    Every method reads the policy once, so one evaluation never mixes rules
    from two versions.
    """

    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    @property
    def policy(self) -> Policy:
        return self._policy

    def replace(self, policy: Policy) -> Policy:
        """Swap in a new, already validated policy; returns the previous one."""
        previous, self._policy = self._policy, policy
        return previous

    def evaluate(self, request: ToolCallRequest) -> Decision:
        policy = self._policy
        matched = [rule for rule in policy.rules if rule_matches(rule, request)]
        if not matched:
            return Decision(
                effect=policy.default,
                rule_id=None,
                reason=f"no rule matched; default is {policy.default.value}",
            )

        winner = max(matched, key=lambda r: r.effect.precedence)
        # max() returns the first maximal element, i.e. first in document order.
        return Decision(
            effect=winner.effect,
            rule_id=winner.id,
            reason=winner.description or f"matched rule {winner.id!r}",
            matched_rule_ids=tuple(r.id for r in matched),
        )

    def always_denied(self, agent: str, server: str, tool: str) -> bool:
        """Whether every possible call of ``tool`` would be denied.

        Arguments are unknown when a tool is listed, so conditional rules count
        as "might match": a conditional ``deny`` cannot hide a tool, and a
        conditional ``allow`` keeps it visible. A tool is hidden only when an
        unconditional ``deny`` applies, or when nothing could ever permit it and
        the default is ``deny``. Every call is still checked with its real
        arguments, so this only decides what the agent is shown.
        """
        return _always_denied(self._policy, agent, server, tool)

    def visible_tools(self, agent: str, server: str, tools: list[str]) -> list[str]:
        """Filter a tool listing down to tools the agent could ever invoke.

        Tools that would be denied outright are hidden; tools that need approval
        stay visible so the agent can request them.
        """
        policy = self._policy
        return [tool for tool in tools if not _always_denied(policy, agent, server, tool)]

    def rate_limits_for(self, agent: str, server: str, tool: str) -> list[RateLimit]:
        """Every rate limit that applies to a call, in document order."""
        probe = ToolCallRequest(agent, server, tool)
        return [limit for limit in self._policy.rate_limits if _identity_matches(limit, probe)]

    def budgets_for(self, agent: str, server: str, tool: str) -> list[Budget]:
        """Every budget that applies to a call, in document order."""
        probe = ToolCallRequest(agent, server, tool)
        return [budget for budget in self._policy.budgets if _identity_matches(budget, probe)]
