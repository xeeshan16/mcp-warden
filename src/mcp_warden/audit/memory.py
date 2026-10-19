"""In-process audit store: for a single gateway, development and tests.

Events live in a bounded ring: past ``max_events`` the oldest are dropped, so
a busy gateway cannot run out of memory because of its own audit trail. Use
the database store for anything that has to survive a restart.
"""

from __future__ import annotations

import threading
from collections import deque
from collections.abc import Sequence
from datetime import datetime

from mcp_warden.audit.model import AuditEvent, AuditPage, AuditQuery, page_from

DEFAULT_MAX_EVENTS = 10_000


class InMemoryAuditStore:
    def __init__(self, max_events: int = DEFAULT_MAX_EVENTS) -> None:
        if max_events < 1:
            raise ValueError("max_events must be at least 1")
        self._events: deque[AuditEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._events)

    def append(self, events: Sequence[AuditEvent]) -> None:
        with self._lock:
            self._events.extend(events)

    def query(self, query: AuditQuery) -> AuditPage:
        with self._lock:
            events = list(self._events)
        # Arrival order is not occurred_at order when calls overlap, so sort.
        matches = sorted(
            (e for e in events if query.matches(e)),
            key=lambda e: (e.occurred_at, e.id),
            reverse=True,
        )
        return page_from(matches[: query.limit + 1], query.limit)

    def prune(self, before: datetime) -> int:
        with self._lock:
            kept = [e for e in self._events if e.occurred_at >= before]
            removed = len(self._events) - len(kept)
            self._events.clear()
            self._events.extend(kept)
        return removed
