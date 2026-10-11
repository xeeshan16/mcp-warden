"""Typed policy document model.

A policy is a versioned list of rules. Each rule targets agents, upstream MCP
servers and tools by glob pattern and carries one effect. The model is strict:
unknown keys are rejected so that typos in a policy file fail loudly instead of
silently widening access.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Effect(StrEnum):
    """Outcome of a rule. Ordered by precedence: deny > require_approval > allow."""

    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"

    @property
    def precedence(self) -> int:
        return _PRECEDENCE[self]


_PRECEDENCE = {Effect.ALLOW: 0, Effect.REQUIRE_APPROVAL: 1, Effect.DENY: 2}

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


class Rule(BaseModel):
    """A single policy rule.

    ``agents``, ``servers`` and ``tools`` are lists of case-sensitive glob
    patterns (``*``, ``?`` and ``[seq]``). A rule matches a request when every
    one of the three lists has at least one matching pattern.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
    effect: Effect
    description: str = ""
    agents: list[str] = Field(default_factory=lambda: ["*"])
    servers: list[str] = Field(default_factory=lambda: ["*"])
    tools: list[str] = Field(default_factory=lambda: ["*"])

    @field_validator("agents", "servers", "tools")
    @classmethod
    def _check_patterns(cls, value: list[str]) -> list[str]:
        return _validate_patterns(value)


class Policy(BaseModel):
    """A complete policy document."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = Field(ge=1, le=1)
    default: Effect = Effect.DENY
    rules: list[Rule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> Policy:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id: {rule.id!r}")
            seen.add(rule.id)
        return self
