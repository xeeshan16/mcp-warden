"""Turning a policy's ``rate_limits`` into bucket checks for a call.

Each limit that matches a ``tools/call`` contributes one bucket: per agent
(``scope: agent``) or per agent, server and tool (``scope: tool``). The call
needs a token from all of them. Buckets are keyed by the limit id, so editing
a limit's numbers keeps the current levels (clamped to the new size), while
renaming it starts afresh.
"""

from __future__ import annotations

import json
import math
from collections.abc import Sequence
from typing import Protocol

from mcp_warden.jsonrpc import ErrorCode, JsonRpcError
from mcp_warden.policy import LimitScope, PolicyEngine, RateLimit
from mcp_warden.ratelimit.bucket import Acquisition, BucketSpec


class BucketStore(Protocol):
    async def acquire(self, specs: Sequence[BucketSpec], cost: float = 1.0) -> Acquisition: ...


def bucket_key(limit: RateLimit, agent: str, server: str, tool: str) -> str:
    parts = (
        [limit.id, agent] if limit.scope is LimitScope.AGENT else [limit.id, agent, server, tool]
    )
    # JSON keeps the key unambiguous whatever characters the names contain.
    return json.dumps(parts, separators=(",", ":"))


def retry_after_seconds(wait: float) -> int:
    """Whole seconds, rounded up, never below one (the ``Retry-After`` header format)."""
    return max(1, math.ceil(wait))


class RateLimitedError(JsonRpcError):
    """``RATE_LIMITED``, with the wait in whole seconds for ``Retry-After``."""

    def __init__(self, message: str, data: dict[str, object], retry_after: int) -> None:
        super().__init__(ErrorCode.RATE_LIMITED, message, data)
        self.retry_after = retry_after


class RateLimiter:
    def __init__(self, engine: PolicyEngine, store: BucketStore) -> None:
        self.engine = engine
        self.store = store

    def specs_for(self, agent: str, server: str, tool: str) -> list[tuple[RateLimit, BucketSpec]]:
        return [
            (
                limit,
                BucketSpec(
                    bucket_key(limit, agent, server, tool),
                    limit.capacity,
                    limit.refill_per_second,
                ),
            )
            for limit in self.engine.rate_limits_for(agent, server, tool)
        ]

    async def check_call(self, agent: str, server: str, tool: str) -> None:
        """Take a token for the call or raise ``RATE_LIMITED``."""
        pairs = self.specs_for(agent, server, tool)
        if not pairs:
            return
        result = await self.store.acquire([spec for _, spec in pairs])
        if result.allowed:
            return
        limit = next(lim for lim, spec in pairs if spec.key == result.limiting_key)
        retry_after = retry_after_seconds(result.retry_after)
        raise RateLimitedError(
            f"rate limit exceeded: {limit.id}",
            {
                "server": server,
                "tool": tool,
                "limit_id": limit.id,
                "scope": limit.scope.value,
                "requests": limit.requests,
                "per": limit.per.value,
                "burst": limit.capacity,
                "retry_after": retry_after,
            },
            retry_after,
        )
