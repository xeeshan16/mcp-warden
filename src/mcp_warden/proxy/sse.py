"""Incremental parser for ``text/event-stream`` bodies.

Streamable HTTP MCP servers may answer a POST with an SSE stream that carries
one or more JSON-RPC messages. Only the parts of the SSE format MCP uses are
interpreted: ``data`` lines (joined with newlines), ``event`` and ``id``.
Comment lines and unknown fields are ignored, as the format requires.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SseEvent:
    data: str
    event: str = "message"
    id: str | None = None


class SseDecoder:
    """Feed lines in, get complete events out."""

    def __init__(self) -> None:
        self._data: list[str] = []
        self._event: str | None = None
        self._id: str | None = None

    def feed(self, line: str) -> SseEvent | None:
        line = line.rstrip("\r\n")
        if line == "":
            return self._dispatch()
        if line.startswith(":"):
            return None
        name, sep, value = line.partition(":")
        if sep and value.startswith(" "):
            value = value[1:]
        if name == "data":
            self._data.append(value)
        elif name == "event":
            self._event = value
        elif name == "id" and "\0" not in value:
            self._id = value
        return None

    def flush(self) -> SseEvent | None:
        """Dispatch a trailing event that was not followed by a blank line."""
        return self._dispatch()

    def _dispatch(self) -> SseEvent | None:
        if not self._data:
            self._event = None
            return None
        event = SseEvent(data="\n".join(self._data), event=self._event or "message", id=self._id)
        self._data = []
        self._event = None
        return event


async def iter_sse_events(lines: AsyncIterator[str]) -> AsyncIterator[SseEvent]:
    decoder = SseDecoder()
    async for line in lines:
        event = decoder.feed(line)
        if event is not None:
            yield event
    tail = decoder.flush()
    if tail is not None:
        yield tail
