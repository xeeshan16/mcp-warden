"""Applying the policy to MCP traffic.

Two points in a session carry policy-relevant information:

* ``tools/call`` requests are evaluated with the agent, upstream, tool name
  and arguments before anything is forwarded. A ``deny`` becomes a
  ``POLICY_DENIED`` error and a ``require_approval`` becomes
  ``APPROVAL_REQUIRED`` (parking the call for a human arrives with the
  approval workflow); the upstream never sees either call.
* ``tools/list`` responses are filtered so the agent is not shown tools it
  can never call. Conditional rules keep a tool visible, because the
  arguments are only known at call time.

A ``tools/list`` result the gateway cannot read is refused rather than
forwarded unfiltered: failing closed is the only safe choice for a filter.

Agent identity is read from the ``X-Warden-Agent`` header for now. It is a
placeholder that per-agent API keys replace; until then it is only as
trustworthy as the network in front of the gateway.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from mcp_warden.jsonrpc import ErrorCode, JsonRpcError, JsonRpcSuccess, success_response
from mcp_warden.jsonrpc.mcp import CallToolParams, parse_list_tools_result
from mcp_warden.policy import Decision, Effect, PolicyEngine, ToolCallRequest

AGENT_HEADER = "x-warden-agent"
ANONYMOUS_AGENT = "anonymous"
_AGENT_ID = re.compile(r"^[A-Za-z0-9_.:@-]{1,100}$")


def agent_from_headers(headers: Mapping[str, str]) -> str:
    """Return the calling agent's id, or raise ``INVALID_REQUEST``.

    A missing header means ``anonymous``, which policies can target like any
    other agent (and which the default ``deny`` covers).
    """
    lowered = {k.lower(): v for k, v in headers.items()}
    raw = lowered.get(AGENT_HEADER)
    if raw is None:
        return ANONYMOUS_AGENT
    agent = raw.strip()
    if not _AGENT_ID.fullmatch(agent):
        raise JsonRpcError(ErrorCode.INVALID_REQUEST, f"invalid {AGENT_HEADER} header")
    return agent


def _decision_data(decision: Decision, server: str, tool: str) -> dict[str, Any]:
    return {
        "server": server,
        "tool": tool,
        "effect": decision.effect.value,
        "rule_id": decision.rule_id,
        "reason": decision.reason,
    }


class PolicyGuard:
    """Policy checks for one gateway; stateless apart from the engine."""

    def __init__(self, engine: PolicyEngine) -> None:
        self.engine = engine

    def check_call(self, agent: str, server: str, params: CallToolParams) -> Decision:
        """Evaluate a ``tools/call``; raise a JSON-RPC error unless it is allowed."""
        decision = self.engine.evaluate(
            ToolCallRequest(agent, server, params.name, params.arguments)
        )
        if decision.effect is Effect.DENY:
            raise JsonRpcError(
                ErrorCode.POLICY_DENIED,
                f"tool call denied by policy: {params.name}",
                _decision_data(decision, server, params.name),
            )
        if decision.effect is Effect.REQUIRE_APPROVAL:
            raise JsonRpcError(
                ErrorCode.APPROVAL_REQUIRED,
                f"tool call requires human approval: {params.name}",
                _decision_data(decision, server, params.name),
            )
        return decision

    def filter_tools(self, agent: str, server: str, response: JsonRpcSuccess) -> JsonRpcSuccess:
        """Drop tools the agent can never call from a ``tools/list`` result.

        Everything else in the result (pagination cursor, fields from newer
        MCP revisions, each tool's own members) is forwarded untouched.
        """
        try:
            parse_list_tools_result(response.result)
        except JsonRpcError as exc:
            raise JsonRpcError(
                ErrorCode.UPSTREAM_ERROR,
                "upstream returned an invalid tools/list result",
                {"server": server},
            ) from exc
        result: dict[str, Any] = dict(response.result)
        result["tools"] = [
            tool
            for tool in result["tools"]
            if not self.engine.always_denied(agent, server, tool["name"])
        ]
        return success_response(response.id, result)
