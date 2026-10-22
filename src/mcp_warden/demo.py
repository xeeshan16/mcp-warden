"""A scripted agent that walks through what the gateway does, end to end.

``mcp-warden demo`` plays two parts against a running gateway: an operator
using the admin API (onboard an agent, issue a key, approve a call, revoke the
key, read the audit log) and an MCP client using that key. Every step states
what it expects, so the script doubles as a smoke test: it exits non-zero when
the gateway behaves differently.

It is written for the example policy (``examples/policy.yaml``) and the fake
upstream registered as ``demo``. It can be repeated against the same database:
the agent is reused, and the approval uses a title unique to the run.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from mcp_warden.jsonrpc.errors import ErrorCode
from mcp_warden.jsonrpc.mcp import LATEST_PROTOCOL_VERSION

# The longest the demo waits for a rate limit to refill before a step that
# must not be refused (only relevant when it is repeated within a minute).
MAX_RETRY_WAIT_SECONDS = 30.0


class DemoError(Exception):
    """The gateway answered differently from what the step expected."""


@dataclass(frozen=True, slots=True)
class RpcReply:
    status: int
    body: dict[str, Any]

    @property
    def error(self) -> dict[str, Any] | None:
        error = self.body.get("error")
        return error if isinstance(error, dict) else None

    @property
    def error_code(self) -> int | None:
        return None if self.error is None else int(self.error["code"])

    @property
    def error_data(self) -> dict[str, Any]:
        data = (self.error or {}).get("data")
        return data if isinstance(data, dict) else {}

    @property
    def result(self) -> dict[str, Any]:
        result = self.body.get("result")
        if not isinstance(result, dict):
            raise DemoError(f"expected a result, got {self.body}")
        return result

    def text(self) -> str:
        """The first text block of a tool result."""
        for block in self.result.get("content", []):
            if block.get("type") == "text":
                return str(block["text"])
        return ""


@dataclass
class DemoReport:
    passed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failed


class Demo:
    """The scripted walkthrough. ``client`` points at the gateway."""

    def __init__(
        self,
        client: httpx.Client,
        admin_token: str,
        *,
        server: str = "demo",
        agent: str = "support-bot",
        metrics_token: str | None = None,
        out: Callable[[str], None] = print,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.client = client
        self.admin_headers = {"authorization": f"Bearer {admin_token}"}
        self.metrics_token = metrics_token
        self.server = server
        self.agent = agent
        self.out = out
        self.sleep = sleep
        self.run_id = uuid.uuid4().hex[:6]
        self.report = DemoReport()
        self._key: str | None = None
        self._key_prefix: str | None = None
        self._session: str | None = None
        self._next_id = 0
        self._started = datetime.now(UTC)

    # --- plumbing ---------------------------------------------------------

    def _admin(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        return self.client.request(method, path, headers=self.admin_headers, **kwargs)

    def _rpc(self, method: str, params: dict[str, Any] | None = None) -> RpcReply:
        self._next_id += 1
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        if params is not None:
            message["params"] = params
        return self._post(message)

    def _post(self, message: dict[str, Any]) -> RpcReply:
        headers = {"accept": "application/json, text/event-stream"}
        if self._key is not None:
            headers["authorization"] = f"Bearer {self._key}"
        if self._session is not None:
            headers["mcp-session-id"] = self._session
        resp = self.client.post(f"/mcp/{self.server}", json=message, headers=headers)
        if resp.status_code == 202:
            return RpcReply(202, {})
        try:
            body = resp.json()
        except ValueError as exc:
            raise DemoError(f"{message.get('method')}: not JSON ({resp.status_code})") from exc
        if session := resp.headers.get("mcp-session-id"):
            self._session = session
        return RpcReply(resp.status_code, body if isinstance(body, dict) else {"batch": body})

    def _call(self, tool: str, arguments: dict[str, Any], *, patient: bool = False) -> RpcReply:
        """``tools/call``; ``patient`` waits out a rate limit once instead of failing."""
        reply = self._rpc("tools/call", {"name": tool, "arguments": arguments})
        if patient and reply.error_code == ErrorCode.RATE_LIMITED:
            wait = min(float(reply.error_data.get("retry_after", 1)), MAX_RETRY_WAIT_SECONDS)
            self.out(f"    (rate limited from an earlier run; waiting {wait:g}s)")
            self.sleep(wait)
            reply = self._rpc("tools/call", {"name": tool, "arguments": arguments})
        return reply

    @contextmanager
    def step(self, title: str) -> Iterator[None]:
        self.out(f"\n▶ {title}")
        try:
            yield
        except (DemoError, httpx.HTTPError, KeyError, ValueError) as exc:
            self.report.failed.append(title)
            self.out(f"  ✘ {exc}")
        else:
            self.report.passed.append(title)

    def _expect_error(self, reply: RpcReply, code: ErrorCode) -> dict[str, Any]:
        if reply.error_code != code:
            raise DemoError(f"expected error {int(code)} ({code.name}), got {reply.body}")
        return reply.error_data

    def _ok(self, message: str) -> None:
        self.out(f"  ✔ {message}")

    # --- the walkthrough --------------------------------------------------

    def wait_until_ready(self, timeout: float = 60.0) -> None:
        deadline = time.monotonic() + timeout
        while True:
            try:
                if self.client.get("/healthz").status_code == 200:
                    return
            except httpx.TransportError:
                pass
            if time.monotonic() >= deadline:
                raise DemoError(f"gateway not ready after {timeout:g}s")
            self.sleep(1.0)

    def run(self) -> DemoReport:
        steps = [
            self.onboard,
            self.connect,
            self.list_tools,
            self.allowed_calls,
            self.denied_calls,
            self.approval,
            self.rate_limit,
            self.revoke,
            self.audit,
            self.metrics,
        ]
        for run_step in steps:
            run_step()
            if self._key is None and run_step == self.onboard:
                break  # nothing else can work without a key
        self.out(
            f"\n{len(self.report.passed)} of {len(self.report.passed) + len(self.report.failed)}"
            " steps behaved as expected"
            + (f"; failed: {', '.join(self.report.failed)}" if self.report.failed else "")
        )
        return self.report

    def onboard(self) -> None:
        with self.step(f"Operator onboards agent {self.agent!r} and issues an API key"):
            resp = self._admin("POST", "/v1/agents", json={"name": self.agent})
            if resp.status_code == 201:
                self._ok(f"agent {self.agent} created")
            elif resp.status_code == 409:
                self._ok(f"agent {self.agent} already exists; reusing it")
            else:
                raise DemoError(f"creating the agent: {resp.status_code} {resp.text}")
            resp = self._admin(
                "POST", f"/v1/agents/{self.agent}/keys", json={"label": f"demo {self.run_id}"}
            )
            if resp.status_code != 201:
                raise DemoError(f"issuing a key: {resp.status_code} {resp.text}")
            issued = resp.json()
            self._key, self._key_prefix = issued["key"], issued["prefix"]
            self._ok(f"key {issued['prefix']}… issued (the full key is shown once, never stored)")

    def connect(self) -> None:
        with self.step("Agent opens an MCP session through the gateway"):
            reply = self._rpc(
                "initialize",
                {
                    "protocolVersion": LATEST_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-warden-demo-agent", "version": "1"},
                },
            )
            info = reply.result["serverInfo"]
            self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
            if self._session is None:
                raise DemoError("the upstream did not assign a session")
            self._ok(
                f"connected to {info['name']} {info['version']}, "
                f"protocol {reply.result['protocolVersion']}"
            )

    def list_tools(self) -> None:
        with self.step("tools/list only shows what the policy could allow"):
            names = [t["name"] for t in self._rpc("tools/list").result["tools"]]
            if "delete_records" in names:
                raise DemoError(f"delete_records should be hidden, got {names}")
            self._ok(f"visible: {', '.join(names)} (delete_records is hidden)")

    def allowed_calls(self) -> None:
        with self.step("Allowed calls are forwarded"):
            forecast = self._call("get_forecast", {"city": "Lisbon"}, patient=True)
            self._ok(f"get_forecast → {forecast.text()}  [rule read-only-everywhere]")
            total = self._call("add", {"a": 2, "b": 40}, patient=True)
            self._ok(f"add 2 + 40 → {total.text()}  [rule demo-basics]")

    def denied_calls(self) -> None:
        with self.step("Denied calls never reach the upstream"):
            data = self._expect_error(
                self._call("delete_records", {"table": "customers"}), ErrorCode.POLICY_DENIED
            )
            self._ok(f"delete_records → -32001 denied by rule {data.get('rule_id')}")
            data = self._expect_error(self._call("sleep", {"seconds": 10}), ErrorCode.POLICY_DENIED)
            self._ok(f"sleep 10s → -32001 denied by argument rule {data.get('rule_id')}")

    def approval(self) -> None:
        with self.step("A risky call waits for a human"):
            args = {"title": f"Checkout is down (demo {self.run_id})", "priority": "urgent"}
            data = self._expect_error(
                self._call("create_ticket", args, patient=True), ErrorCode.APPROVAL_REQUIRED
            )
            approval_id = data["approval_id"]
            self._ok(f"urgent create_ticket → -32002 pending approval {approval_id}")
            resp = self._admin(
                "POST", f"/v1/approvals/{approval_id}/approve", json={"note": "on-call agrees"}
            )
            if resp.status_code != 200:
                raise DemoError(f"approving: {resp.status_code} {resp.text}")
            self._ok(f"operator approves it (decided by {resp.json()['decided_by']})")
            reply = self._call("create_ticket", args, patient=True)
            self._ok(f"agent repeats the identical call → {reply.text()}")

    def rate_limit(self) -> None:
        with self.step("A burst of ticket creation hits the rate limit"):
            for attempt in range(1, 6):
                reply = self._call("create_ticket", {"title": f"Routine {self.run_id}-{attempt}"})
                if reply.error_code == ErrorCode.RATE_LIMITED:
                    data = reply.error_data
                    self._ok(
                        f"call {attempt} → -32003 rate limited by {data.get('limit_id')}, "
                        f"retry after {data.get('retry_after')}s"
                    )
                    return
                self._ok(f"call {attempt} → {reply.text()}")
            raise DemoError("five calls in a row were not rate limited")

    def revoke(self) -> None:
        with self.step("Revoking the key cuts the agent off on its next request"):
            resp = self._admin("POST", f"/v1/keys/{self._key_prefix}/revoke")
            if resp.status_code != 200:
                raise DemoError(f"revoking: {resp.status_code} {resp.text}")
            reply = self._call("echo", {"text": "still there?"})
            if reply.status != 401:
                raise DemoError(f"expected HTTP 401 after revoking, got {reply.status}")
            self._ok(f"key {self._key_prefix}… revoked; the next call gets HTTP 401")

    def audit(self) -> None:
        with self.step("The audit log has the metadata of every call, never the payloads"):
            since = self._started.isoformat().replace("+00:00", "Z")
            resp = self._admin(
                "GET",
                "/v1/audit",
                params={"agent": self.agent, "method": "tools/call", "since": since},
            )
            if resp.status_code != 200:
                raise DemoError(f"reading the audit log: {resp.status_code} {resp.text}")
            events = list(reversed(resp.json()["events"]))
            if not events:
                raise DemoError("no audit events for this run")
            self.out(f"    {'tool':<15} {'outcome':<16} {'rule':<28} {'args':>5}")
            for event in events:
                self.out(
                    f"    {event['tool'] or '-':<15} {event['outcome']:<16} "
                    f"{event['rule_id'] or '-':<28} {event['arguments_size']:>4}B"
                )
            self._ok(f"{len(events)} tool calls recorded with argument digests and sizes only")

    def metrics(self) -> None:
        with self.step("Prometheus metrics count the decisions"):
            headers = {}
            if self.metrics_token:
                headers["authorization"] = f"Bearer {self.metrics_token}"
            resp = self.client.get("/metrics", headers=headers)
            if resp.status_code == 404:
                self._ok("metrics are turned off on this gateway; skipped")
                return
            if resp.status_code != 200:
                raise DemoError(f"reading metrics: {resp.status_code}")
            lines = [
                line
                for line in resp.text.splitlines()
                if line.startswith("mcp_warden_policy_decisions_total{")
            ]
            if not lines:
                raise DemoError("no mcp_warden_policy_decisions_total samples")
            for line in sorted(lines):
                self.out(f"    {line}")
            self._ok(f"{len(lines)} decision series exported")
