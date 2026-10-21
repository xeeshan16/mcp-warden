"""Keeping metric label values bounded.

Prometheus stores one time series per distinct combination of label values,
so a label fed from agent-controlled input is a memory problem waiting to
happen: an agent that calls a million made-up tool names (each one denied by
policy) would otherwise create a million series in the gateway and in every
Prometheus that scrapes it.

Two defences:

* JSON-RPC methods are reported as themselves only when they are MCP methods
  the gateway knows; anything else is ``other``.
* Values that are bounded only by configuration in the normal case (agents,
  tools) go through a :class:`LabelGuard`, which admits the first ``limit``
  distinct values per label and reports the rest as ``__other__``. Overflow
  is counted so that an operator can raise the limit or find the cause.
"""

from __future__ import annotations

import threading
from collections.abc import Callable

OVERFLOW = "__other__"
NONE = ""

# Client-to-server request methods of the MCP specification.
KNOWN_METHODS: frozenset[str] = frozenset(
    {
        "initialize",
        "ping",
        "tools/list",
        "tools/call",
        "resources/list",
        "resources/read",
        "resources/templates/list",
        "resources/subscribe",
        "resources/unsubscribe",
        "prompts/list",
        "prompts/get",
        "completion/complete",
        "logging/setLevel",
    }
)


def method_label(method: str) -> str:
    """``method`` if it is a known MCP method, else ``other``."""
    return method if method in KNOWN_METHODS else "other"


class LabelGuard:
    """Admits at most ``limit`` distinct values per label name."""

    def __init__(self, limit: int, on_overflow: Callable[[str], None] | None = None) -> None:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        self.limit = limit
        self._seen: dict[str, set[str]] = {}
        self._lock = threading.Lock()
        self._on_overflow = on_overflow

    def __call__(self, label: str, value: str | None) -> str:
        if value is None:
            return NONE
        with self._lock:
            seen = self._seen.setdefault(label, set())
            if value in seen:
                return value
            if len(seen) < self.limit:
                seen.add(value)
                return value
        if self._on_overflow is not None:
            self._on_overflow(label)
        return OVERFLOW

    def size(self, label: str) -> int:
        with self._lock:
            return len(self._seen.get(label, ()))
