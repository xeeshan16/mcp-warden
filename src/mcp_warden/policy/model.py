"""Typed policy document model.

A policy is a versioned list of rules. Each rule targets agents, upstream MCP
servers and one kind of capability (tools, prompts or resources) by glob
pattern and carries one effect. The model is strict: unknown keys are rejected
so that typos in a policy file fail loudly instead of silently widening access.
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)


class Effect(StrEnum):
    """Outcome of a rule. Ordered by precedence: deny > require_approval > allow."""

    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"

    @property
    def precedence(self) -> int:
        return _PRECEDENCE[self]


_PRECEDENCE = {Effect.ALLOW: 0, Effect.REQUIRE_APPROVAL: 1, Effect.DENY: 2}


class Target(StrEnum):
    """The kind of MCP capability a request uses and a rule applies to.

    Tools are matched by name (``tools/call``), prompts by name
    (``prompts/get``) and resources by URI (``resources/read`` and
    ``resources/subscribe``).
    """

    TOOL = "tool"
    PROMPT = "prompt"
    RESOURCE = "resource"


_MAX_PATTERN_LEN = 200


def _validate_patterns(patterns: list[str]) -> list[str]:
    if not patterns:
        raise ValueError("must contain at least one pattern (use '*' to match everything)")
    cleaned: list[str] = []
    for raw in patterns:
        pattern = raw.strip()
        if not pattern:
            raise ValueError("patterns must not be blank")
        if len(pattern) > _MAX_PATTERN_LEN:
            raise ValueError(f"pattern longer than {_MAX_PATTERN_LEN} characters")
        cleaned.append(pattern)
    return cleaned


JsonScalar = StrictBool | StrictInt | StrictFloat | StrictStr | None
Number = StrictInt | StrictFloat

_MAX_REGEX_LEN = 500
_MAX_ONE_OF = 100
_MAX_MATCHERS = 20

# Operators an argument matcher may use. ``min`` and ``max`` may be combined
# into a range; every other operator stands alone so a matcher reads as one
# unambiguous condition.
_OPERATORS = ("equals", "one_of", "glob", "regex", "present", "max_length", "min", "max")


class ArgumentMatcher(BaseModel):
    """A condition on one ``tools/call`` argument.

    ``path`` addresses a value inside the call's ``arguments`` object with dot
    notation (``options.mode``); a purely numeric segment indexes into a list
    (``files.0``). Exactly one operator is given:

    * ``equals`` / ``one_of``: JSON-typed equality (``1`` never equals ``true``);
    * ``glob`` / ``regex``: string values only; ``regex`` must match the whole value;
    * ``present``: whether the path resolves at all;
    * ``max_length``: length of a string, list or object;
    * ``min`` / ``max``: inclusive numeric bounds (booleans are not numbers).

    A missing value never satisfies an operator other than ``present: false``.
    ``not: true`` negates the result, so ``{path: env, equals: prod, not: true}``
    also holds when ``env`` is absent.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    path: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9_$-]+(\.[A-Za-z0-9_$-]+)*$",
    )
    equals: JsonScalar = None
    one_of: list[JsonScalar] | None = Field(default=None, min_length=1, max_length=_MAX_ONE_OF)
    glob: StrictStr | None = Field(default=None, min_length=1, max_length=_MAX_PATTERN_LEN)
    regex: StrictStr | None = Field(default=None, min_length=1, max_length=_MAX_REGEX_LEN)
    present: StrictBool | None = None
    max_length: StrictInt | None = Field(default=None, ge=0)
    min: Number | None = None
    max: Number | None = None
    negate: StrictBool = Field(default=False, alias="not")

    @property
    def operators(self) -> tuple[str, ...]:
        return tuple(op for op in _OPERATORS if op in self.model_fields_set)

    @field_validator("regex")
    @classmethod
    def _check_regex(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"invalid regular expression: {exc}") from exc
        return value

    @model_validator(mode="after")
    def _one_operator(self) -> ArgumentMatcher:
        ops = self.operators
        if not ops:
            raise ValueError(f"matcher for {self.path!r} needs one of: {', '.join(_OPERATORS)}")
        if len(ops) > 1 and set(ops) != {"min", "max"}:
            raise ValueError(
                f"matcher for {self.path!r} combines {', '.join(ops)}; "
                "use one operator per matcher (only min and max may be combined)"
            )
        for op in ("one_of", "glob", "regex", "present", "max_length"):
            if op in ops and getattr(self, op) is None:
                raise ValueError(f"{op} must not be null")
        if ("min" in ops and self.min is None) or ("max" in ops and self.max is None):
            raise ValueError("min and max must be numbers")
        if self.min is not None and self.max is not None and self.min > self.max:
            raise ValueError(f"min ({self.min}) is greater than max ({self.max})")
        return self


class Rule(BaseModel):
    """A single policy rule.

    ``agents`` and ``servers`` are lists of case-sensitive glob patterns
    (``*``, ``?`` and ``[seq]``). A rule applies to exactly one kind of
    capability, chosen by which of ``tools``, ``prompts`` or ``resources`` it
    lists (tool names, prompt names or resource URIs, also globs; ``*`` matches
    ``/`` too). A rule that names none of them is a tool rule for every tool,
    as before prompts and resources were policed.

    A rule matches a request of its kind when every pattern list has at least
    one matching pattern and every entry in ``arguments`` holds for the
    request's arguments (``tools/call`` arguments or ``prompts/get``
    arguments; resources take none).

    A rule with argument matchers is *conditional*: it can only be decided
    once the arguments are known, which matters for filtering listings.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
    effect: Effect
    description: str = ""
    agents: list[str] = Field(default_factory=lambda: ["*"])
    servers: list[str] = Field(default_factory=lambda: ["*"])
    tools: list[str] = Field(default_factory=lambda: ["*"])
    prompts: list[str] | None = None
    resources: list[str] | None = None
    arguments: list[ArgumentMatcher] = Field(default_factory=list, max_length=_MAX_MATCHERS)

    @field_validator("agents", "servers", "tools")
    @classmethod
    def _check_patterns(cls, value: list[str]) -> list[str]:
        return _validate_patterns(value)

    @field_validator("prompts", "resources")
    @classmethod
    def _check_optional_patterns(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else _validate_patterns(value)

    @model_validator(mode="after")
    def _one_target(self) -> Rule:
        given = [
            key
            for key, present in (
                ("tools", "tools" in self.model_fields_set),
                ("prompts", self.prompts is not None),
                ("resources", self.resources is not None),
            )
            if present
        ]
        if len(given) > 1:
            raise ValueError(
                f"rule {self.id!r} lists {' and '.join(given)}; "
                "a rule applies to one of tools, prompts or resources"
            )
        if self.resources is not None and self.arguments:
            raise ValueError(f"rule {self.id!r}: resources take no arguments to match")
        if self.target is not Target.TOOL and self.effect is Effect.REQUIRE_APPROVAL:
            raise ValueError(
                f"rule {self.id!r}: require_approval is only available for tools; "
                "prompts and resources are allowed or denied"
            )
        return self

    @property
    def target(self) -> Target:
        if self.prompts is not None:
            return Target.PROMPT
        if self.resources is not None:
            return Target.RESOURCE
        return Target.TOOL

    @property
    def names(self) -> list[str]:
        """The patterns for this rule's kind of capability."""
        if self.prompts is not None:
            return self.prompts
        if self.resources is not None:
            return self.resources
        return self.tools

    @property
    def conditional(self) -> bool:
        return bool(self.arguments)


class LimitScope(StrEnum):
    """What one token bucket of a rate limit is shared by."""

    # One bucket per agent, shared by every call the limit matches.
    AGENT = "agent"
    # One bucket per agent, server and tool.
    TOOL = "tool"


class Period(StrEnum):
    SECOND = "second"
    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"

    @property
    def seconds(self) -> int:
        return _PERIOD_SECONDS[self]


_PERIOD_SECONDS = {Period.SECOND: 1, Period.MINUTE: 60, Period.HOUR: 3600, Period.DAY: 86400}

_MAX_RATE_LIMITS = 100
_MAX_REQUESTS = 1_000_000


class RateLimit(BaseModel):
    """A token-bucket limit on ``tools/call`` requests.

    ``requests`` per ``per`` is the sustained rate; ``burst`` is the bucket
    size, i.e. how many calls may arrive back to back after a quiet spell
    (defaults to ``requests``). A call must take one token from the bucket of
    every limit that matches it, so limits only ever add restrictions.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
    description: str = ""
    agents: list[str] = Field(default_factory=lambda: ["*"])
    servers: list[str] = Field(default_factory=lambda: ["*"])
    tools: list[str] = Field(default_factory=lambda: ["*"])
    scope: LimitScope = LimitScope.AGENT
    requests: StrictInt = Field(ge=1, le=_MAX_REQUESTS)
    per: Period
    burst: StrictInt | None = Field(default=None, ge=1, le=_MAX_REQUESTS)

    @field_validator("agents", "servers", "tools")
    @classmethod
    def _check_patterns(cls, value: list[str]) -> list[str]:
        return _validate_patterns(value)

    @property
    def capacity(self) -> int:
        return self.burst if self.burst is not None else self.requests

    @property
    def refill_per_second(self) -> float:
        return self.requests / self.per.seconds


class BudgetWindow(StrEnum):
    """A fixed calendar window in UTC; usage resets when the next one starts.

    Weeks start on Monday (ISO 8601), months on the first.
    """

    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"


_MAX_BUDGETS = 100
_MAX_BUDGET_CALLS = 1_000_000_000
_MAX_BUDGET_TOKENS = 1_000_000_000_000


class Budget(BaseModel):
    """A quota on ``tools/call`` usage per fixed window.

    Where a rate limit smooths bursts, a budget caps the total: at most
    ``max_calls`` calls and/or ``max_tokens`` estimated tokens (request
    arguments plus tool results) per ``window``. Usage resets at the start of
    the next window. Every budget that matches a call must have room for it,
    so budgets only ever add restrictions.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
    description: str = ""
    agents: list[str] = Field(default_factory=lambda: ["*"])
    servers: list[str] = Field(default_factory=lambda: ["*"])
    tools: list[str] = Field(default_factory=lambda: ["*"])
    scope: LimitScope = LimitScope.AGENT
    window: BudgetWindow
    max_calls: StrictInt | None = Field(default=None, ge=1, le=_MAX_BUDGET_CALLS)
    max_tokens: StrictInt | None = Field(default=None, ge=1, le=_MAX_BUDGET_TOKENS)

    @field_validator("agents", "servers", "tools")
    @classmethod
    def _check_patterns(cls, value: list[str]) -> list[str]:
        return _validate_patterns(value)

    @model_validator(mode="after")
    def _has_a_limit(self) -> Budget:
        if self.max_calls is None and self.max_tokens is None:
            raise ValueError(f"budget {self.id!r} needs max_calls, max_tokens or both")
        return self


class Policy(BaseModel):
    """A complete policy document."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = Field(ge=1, le=1)
    default: Effect = Effect.DENY
    rules: list[Rule] = Field(default_factory=list)
    rate_limits: list[RateLimit] = Field(default_factory=list, max_length=_MAX_RATE_LIMITS)
    budgets: list[Budget] = Field(default_factory=list, max_length=_MAX_BUDGETS)

    @model_validator(mode="after")
    def _unique_ids(self) -> Policy:
        for kind, ids in (
            ("rule", [r.id for r in self.rules]),
            ("rate limit", [r.id for r in self.rate_limits]),
            ("budget", [b.id for b in self.budgets]),
        ):
            seen: set[str] = set()
            for item_id in ids:
                if item_id in seen:
                    raise ValueError(f"duplicate {kind} id: {item_id!r}")
                seen.add(item_id)
        return self
