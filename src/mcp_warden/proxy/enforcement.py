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
* ``prompts/get`` and ``resources/read`` / ``resources/subscribe`` are
  evaluated the same way against prompt and resource rules, and
  ``prompts/list`` / ``resources/list`` are filtered alike. There is nothing
  to park for a human here, so anything but ``allow`` (``require_approval``
  can only come from the policy's ``default``) is refused.
* ``completion/complete`` for a prompt's argument is refused when the prompt
  itself could never be fetched, so completions do not leak what a hidden
  prompt takes.

Resource templates (``resources/templates/list``) are forwarded unfiltered:
a template is not a URI, and every URI built from one is checked when it is
read.

A listing the gateway cannot read is refused rather than forwarded
unfiltered: failing closed is the only safe choice for a filter.

The agent a decision is made for is the one :mod:`mcp_warden.identity`
authenticated for the request.
"""

from __future__ import annotations

from typing import Any

from mcp_warden.jsonrpc import ErrorCode, JsonRpcError, JsonRpcSuccess, success_response
from mcp_warden.jsonrpc.mcp import (
    CallToolParams,
    CompleteParams,
    GetPromptParams,
    ResourceParams,
    is_valid_resource_uri,
    parse_list_prompts_result,
    parse_list_resources_result,
    parse_list_tools_result,
)
from mcp_warden.policy import Decision, Effect, PolicyEngine, Target, ToolCallRequest

_DATA_KEY = {Target.TOOL: "tool", Target.PROMPT: "prompt", Target.RESOURCE: "uri"}


def _decision_data(
    decision: Decision, server: str, name: str, target: Target = Target.TOOL
) -> dict[str, Any]:
    return {
        "server": server,
        _DATA_KEY[target]: name,
        "effect": decision.effect.value,
        "rule_id": decision.rule_id,
        "reason": decision.reason,
    }


def _invalid_listing(server: str, method: str) -> JsonRpcError:
    return JsonRpcError(
        ErrorCode.UPSTREAM_ERROR,
        f"upstream returned an invalid {method} result",
        {"server": server},
    )


class PolicyGuard:
    """Policy checks for one gateway; stateless apart from the engine."""

    def __init__(self, engine: PolicyEngine) -> None:
        self.engine = engine

    def evaluate_call(self, agent: str, server: str, params: CallToolParams) -> Decision:
        """Evaluate a ``tools/call``; raise ``POLICY_DENIED`` for a deny.

        Returns the decision otherwise, so the caller can route
        ``require_approval`` to the approval gate.
        """
        decision = self.engine.evaluate(
            ToolCallRequest(agent, server, params.name, params.arguments)
        )
        if decision.effect is Effect.DENY:
            raise JsonRpcError(
                ErrorCode.POLICY_DENIED,
                f"tool call denied by policy: {params.name}",
                _decision_data(decision, server, params.name),
            )
        return decision

    def check_call(self, agent: str, server: str, params: CallToolParams) -> Decision:
        """Evaluate a ``tools/call``; raise a JSON-RPC error unless it is allowed."""
        decision = self.evaluate_call(agent, server, params)
        if decision.effect is Effect.REQUIRE_APPROVAL:
            raise JsonRpcError(
                ErrorCode.APPROVAL_REQUIRED,
                f"tool call requires human approval: {params.name}",
                _decision_data(decision, server, params.name),
            )
        return decision

    def _check_other(
        self,
        agent: str,
        server: str,
        target: Target,
        name: str,
        arguments: dict[str, Any] | None = None,
    ) -> Decision:
        decision = self.engine.evaluate(ToolCallRequest(agent, server, name, arguments, target))
        if decision.effect is not Effect.ALLOW:
            raise JsonRpcError(
                ErrorCode.POLICY_DENIED,
                f"{target.value} denied by policy: {name}",
                _decision_data(decision, server, name, target),
            )
        return decision

    def check_prompt(self, agent: str, server: str, params: GetPromptParams) -> Decision:
        """Evaluate a ``prompts/get``; raise ``POLICY_DENIED`` unless it is allowed."""
        return self._check_other(agent, server, Target.PROMPT, params.name, params.arguments)

    def check_resource(self, agent: str, server: str, params: ResourceParams) -> Decision:
        """Evaluate a ``resources/read`` or ``resources/subscribe`` by URI."""
        return self._check_other(agent, server, Target.RESOURCE, params.uri)

    def check_completion(self, agent: str, server: str, params: CompleteParams) -> None:
        """Refuse completions for a prompt the agent could never fetch.

        The prompt's arguments are not known yet, so this asks the same
        question as listing: could any ``prompts/get`` of it be allowed?
        """
        ref = params.ref
        if ref.type != "ref/prompt":
            return
        name = ref.name or ""
        if not name or self.engine.always_denied(agent, server, name, Target.PROMPT):
            raise JsonRpcError(
                ErrorCode.POLICY_DENIED,
                f"prompt denied by policy: {name}",
                {"server": server, "prompt": name, "effect": Effect.DENY.value},
            )

    def filter_prompts(self, agent: str, server: str, response: JsonRpcSuccess) -> JsonRpcSuccess:
        """Drop prompts the agent can never fetch from a ``prompts/list`` result."""
        try:
            parse_list_prompts_result(response.result)
        except JsonRpcError as exc:
            raise _invalid_listing(server, "prompts/list") from exc
        result: dict[str, Any] = dict(response.result)
        result["prompts"] = [
            prompt
            for prompt in result["prompts"]
            if not self.engine.always_denied(agent, server, prompt["name"], Target.PROMPT)
        ]
        return success_response(response.id, result)

    def filter_resources(self, agent: str, server: str, response: JsonRpcSuccess) -> JsonRpcSuccess:
        """Drop resources the agent can never read from a ``resources/list`` result.

        A URI no request could use (see :func:`is_valid_resource_uri`) is
        dropped too, so the agent is never shown something it cannot read.
        """
        try:
            parse_list_resources_result(response.result)
        except JsonRpcError as exc:
            raise _invalid_listing(server, "resources/list") from exc
        result: dict[str, Any] = dict(response.result)
        result["resources"] = [
            resource
            for resource in result["resources"]
            if is_valid_resource_uri(resource["uri"])
            and not self.engine.always_denied(agent, server, resource["uri"], Target.RESOURCE)
        ]
        return success_response(response.id, result)

    def filter_tools(self, agent: str, server: str, response: JsonRpcSuccess) -> JsonRpcSuccess:
        """Drop tools the agent can never call from a ``tools/list`` result.

        Everything else in the result (pagination cursor, fields from newer
        MCP revisions, each tool's own members) is forwarded untouched.
        """
        try:
            parse_list_tools_result(response.result)
        except JsonRpcError as exc:
            raise _invalid_listing(server, "tools/list") from exc
        result: dict[str, Any] = dict(response.result)
        result["tools"] = [
            tool
            for tool in result["tools"]
            if not self.engine.always_denied(agent, server, tool["name"])
        ]
        return success_response(response.id, result)
