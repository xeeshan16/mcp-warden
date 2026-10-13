from __future__ import annotations

import pytest

from mcp_warden.fake_upstream import call_tool


@pytest.mark.anyio
async def test_tools_are_deterministic() -> None:
    first = await call_tool("get_forecast", {"city": "Lahore"})
    second = await call_tool("get_forecast", {"city": " lahore "})
    assert first["structuredContent"]["condition"] == second["structuredContent"]["condition"]
    assert first["structuredContent"]["synthetic"] is True
    a = await call_tool("create_ticket", {"title": "Printer on fire"})
    b = await call_tool("create_ticket", {"title": "Printer on fire"})
    assert a == b
    assert a["content"][0]["text"].startswith("created ticket T-")


@pytest.mark.anyio
async def test_add_and_echo() -> None:
    assert (await call_tool("add", {"a": 2, "b": 3.5}))["structuredContent"] == {"sum": 5.5}
    assert (await call_tool("echo", {"text": "hi"}))["content"][0]["text"] == "hi"


@pytest.mark.anyio
async def test_bad_arguments_are_tool_errors() -> None:
    result = await call_tool("add", {"a": True, "b": 1})
    assert result["isError"] is True


@pytest.mark.anyio
async def test_unknown_tool_raises() -> None:
    with pytest.raises(KeyError):
        await call_tool("nope", {})
