"""The audit store interface shared by the in-memory and database stores.

Stores are synchronous; the gateway calls them from a worker thread.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol

from mcp_warden.audit.model import AuditEvent, AuditPage, AuditQuery


class AuditStore(Protocol):
    def append(self, events: Sequence[AuditEvent]) -> None:
        """Store events; all of them or none."""
        ...

    def query(self, query: AuditQuery) -> AuditPage:
        """Matching events newest first, at most ``query.limit``, with a cursor if more remain."""
        ...

    def prune(self, before: datetime) -> int:
        """Delete events that occurred before ``before``; returns how many."""
        ...
