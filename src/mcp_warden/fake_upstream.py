"""A small, deterministic MCP server used by the tests and the local demo.

It speaks Streamable HTTP on ``POST /mcp`` and exposes a handful of tools whose
names exercise the example policy (read-style, write-style and destructive
tools). Every answer is a pure function of the input, so tests can assert on
exact output; no network, clock or randomness is involved, except the
``sleep`` tool, which exists to test upstream timeouts.

With ``sse=True`` requests are answered with a ``text/event-stream`` that sends
a progress notification before the response, like servers that stream.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from mcp_warden.jsonrpc.mcp import LATEST_PROTOCOL_VERSION, negotiate_protocol_version

SERVER_INFO = {"name": "mcp-warden-fake-upstream", "version": "1.0.0"}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "echo",
        "description": "Return the given text unchanged.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    {
        "name": "add",
        "description": "Add two numbers.",
        "inputSchema": {
            "type": "object",
            "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
            "required": ["a", "b"],
        },
    },
    {
        "name": "get_forecast",
        "description": "A synthetic, deterministic weather forecast for a city.",
        "inputSchema": {
            "type": "object",
            "properties": {"city": {"type": "string"}},
            "required": ["city"],
        },
    },
    {
        "name": "create_ticket",
        "description": "Pretend to open a ticket and return its id.",
        "inputSchema": {
            "type": "object",
            "properties": {"title": {"type": "string"}},
            "required": ["title"],
        },
    },
    {
        "name": "delete_records",
        "description": "Pretend to delete every record in a table.",
        "inputSchema": {
            "type": "object",
            "properties": {"table": {"type": "string"}},
            "required": ["table"],
        },
    },
    {
        "name": "sleep",
        "description": "Wait for up to 5 seconds before answering.",
        "inputSchema": {
            "type": "object",
            "properties": {"seconds": {"type": "number"}},
            "required": ["seconds"],
        },
    },
]

_CONDITIONS = ("sunny", "cloudy", "rain", "windy", "fog")


def _digest(text: str) -> bytes:
    return hashlib.sha256(text.encode("utf-8")).digest()


def _text(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": False}


class _ToolError(Exception):
    pass


def _require(args: dict[str, Any], name: str, kind: type | tuple[type, ...]) -> Any:
    value = args.get(name)
    if not isinstance(value, kind) or isinstance(value, bool):
        raise _ToolError(f"argument {name!r} is required")
    return value


async def call_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Run one fake tool. Tool failures are results with ``isError``, per MCP."""
    try:
        if name == "echo":
            return _text(_require(args, "text", str))
        if name == "add":
            total = _require(args, "a", (int, float)) + _require(args, "b", (int, float))
            return {**_text(str(total)), "structuredContent": {"sum": total}}
        if name == "get_forecast":
            city = _require(args, "city", str)
            d = _digest(city.strip().lower())
            forecast = {
                "city": city,
                "condition": _CONDITIONS[d[0] % len(_CONDITIONS)],
                "high_c": 5 + d[1] % 25,
                "synthetic": True,
            }
            return {**_text(json.dumps(forecast)), "structuredContent": forecast}
        if name == "create_ticket":
            title = _require(args, "title", str)
            return _text(f"created ticket T-{_digest(title).hex()[:8].upper()}")
        if name == "delete_records":
            table = _require(args, "table", str)
            return _text(f"deleted all records from {table} (fake: nothing was touched)")
        if name == "sleep":
            seconds = min(max(float(_require(args, "seconds", (int, float))), 0.0), 5.0)
            await asyncio.sleep(seconds)
            return _text(f"slept {seconds:g}s")
    except _ToolError as exc:
        return {"content": [{"type": "text", "text": str(exc)}], "isError": True}
    raise KeyError(name)


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _result(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def create_fake_upstream(*, sse: bool = False, require_session: bool = True) -> FastAPI:
    app = FastAPI(title="MCP Warden fake upstream")
    sessions: set[str] = set()
    counter = 0

    async def dispatch(message: dict[str, Any]) -> dict[str, Any]:
        nonlocal counter
        request_id = message.get("id")
        method = message.get("method")
        params = message.get("params") or {}
        if method == "initialize":
            counter += 1
            requested = str(params.get("protocolVersion", LATEST_PROTOCOL_VERSION))
            return _result(
                request_id,
                {
                    "protocolVersion": negotiate_protocol_version(requested),
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": SERVER_INFO,
                },
            )
        if method == "ping":
            return _result(request_id, {})
        if method == "tools/list":
            return _result(request_id, {"tools": TOOLS})
        if method == "tools/call":
            name = params.get("name")
            args = params.get("arguments") or {}
            try:
                return _result(request_id, await call_tool(str(name), args))
            except KeyError:
                return _error(request_id, -32602, f"unknown tool: {name}")
        return _error(request_id, -32601, f"method not found: {method}")

    @app.post("/mcp")
    async def mcp(request: Request) -> Response:
        message = json.loads(await request.body())
        if not isinstance(message, dict):
            return JSONResponse(_error(None, -32600, "batches are not supported"), 400)
        is_initialize = message.get("method") == "initialize"
        session = request.headers.get("mcp-session-id")
        if require_session and not is_initialize:
            if session is None:
                return JSONResponse(_error(None, -32600, "missing session"), 400)
            if session not in sessions:
                return Response(status_code=404)
        if "id" not in message or "method" not in message:
            return Response(status_code=202)  # notification or client response

        reply = await dispatch(message)
        headers: dict[str, str] = {}
        if is_initialize and require_session:
            new_session = f"fake-session-{counter}"
            sessions.add(new_session)
            headers["mcp-session-id"] = new_session
        if not sse:
            return JSONResponse(reply, headers=headers)
        progress = {
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {"progressToken": "fake", "progress": 1, "total": 1},
        }
        body = (
            ": keep-alive\n\n"
            f"event: message\ndata: {json.dumps(progress)}\n\n"
            f"event: message\nid: 1\ndata: {json.dumps(reply)}\n\n"
        )
        return Response(body, media_type="text/event-stream", headers=headers)

    return app
