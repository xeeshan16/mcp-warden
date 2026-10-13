from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from mcp_warden.proxy.sse import SseDecoder, SseEvent, iter_sse_events


def feed_all(lines: list[str]) -> list[SseEvent]:
    decoder = SseDecoder()
    events = [e for line in lines if (e := decoder.feed(line)) is not None]
    tail = decoder.flush()
    return [*events, tail] if tail else events


def test_single_event() -> None:
    assert feed_all(["data: {}", ""]) == [SseEvent(data="{}")]


def test_multiline_data_event_and_id() -> None:
    events = feed_all(["event: message", "id: 7", "data: a", "data:b", ""])
    assert events == [SseEvent(data="a\nb", event="message", id="7")]


def test_comments_unknown_fields_and_empty_events_are_ignored() -> None:
    events = feed_all([": keep-alive", "", "retry: 100", "", "data: x", "", ""])
    assert events == [SseEvent(data="x")]


def test_event_name_resets_between_events() -> None:
    events = feed_all(["event: ping", "data: 1", "", "data: 2", ""])
    assert [e.event for e in events] == ["ping", "message"]


def test_crlf_and_trailing_event_without_blank_line() -> None:
    assert feed_all(["data: one\r\n", "\r\n", "data: two"]) == [
        SseEvent(data="one"),
        SseEvent(data="two"),
    ]


@pytest.mark.anyio
async def test_async_iteration() -> None:
    async def lines() -> AsyncIterator[str]:
        for line in ["data: 1", "", "data: 2"]:
            yield line

    assert [e.data async for e in iter_sse_events(lines())] == ["1", "2"]
