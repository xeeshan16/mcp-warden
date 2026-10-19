"""The retention job: removes history the gateway no longer needs.

What it deletes, and when:

* audit events older than the retention period;
* approval requests finished (executed, expired, or with a denial that no
  longer applies) longer ago than the retention period;
* budget usage counters of windows that ended longer ago than the retention
  period (current windows are never touched, so budgets are unaffected);
* rate-limit buckets that have refilled completely; a missing row and a full
  bucket mean the same thing, so these carry no history at all.

The in-memory stores bound themselves and need no job. The job runs from the
CLI (``mcp-warden retention``, e.g. from cron or a Kubernetes CronJob) or
inside the gateway every ``WARDEN_RETENTION_INTERVAL_SECONDS``. Each step is
one short ``DELETE`` and safe to run from several places at once.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta

import anyio
import anyio.to_thread

from mcp_warden.approval import ApprovalStore
from mcp_warden.audit import AuditStore
from mcp_warden.budget import DatabaseUsageStore
from mcp_warden.ratelimit import DatabaseBucketStore

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class RetentionReport:
    """How many rows each step removed; ``None`` when the step had no store to prune."""

    cutoff: datetime
    audit_events: int | None = None
    approval_requests: int | None = None
    usage_counters: int | None = None
    rate_limit_buckets: int | None = None

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = asdict(self)
        data["cutoff"] = self.cutoff.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        return data


class RetentionJob:
    def __init__(
        self,
        keep: timedelta,
        *,
        audit: AuditStore | None = None,
        approvals: ApprovalStore | None = None,
        usage: DatabaseUsageStore | None = None,
        buckets: DatabaseBucketStore | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if keep <= timedelta(0):
            raise ValueError("the retention period must be positive")
        self.keep = keep
        self.audit = audit
        self.approvals = approvals
        self.usage = usage
        self.buckets = buckets
        self._clock = clock or _utcnow

    def run(self) -> RetentionReport:
        cutoff = self._clock() - self.keep
        return RetentionReport(
            cutoff=cutoff,
            audit_events=self.audit.prune(cutoff) if self.audit is not None else None,
            approval_requests=(
                self.approvals.prune(cutoff) if self.approvals is not None else None
            ),
            usage_counters=self.usage.prune(cutoff) if self.usage is not None else None,
            rate_limit_buckets=self.buckets.prune() if self.buckets is not None else None,
        )

    async def run_periodically(
        self,
        interval: float,
        *,
        sleep: Callable[[float], Awaitable[None]] = anyio.sleep,
        runs: int | None = None,
    ) -> None:
        """Run every ``interval`` seconds until cancelled (or ``runs`` times, for tests).

        A failed run is logged and retried at the next interval; it never
        stops the loop, and with it the gateway.
        """
        if interval <= 0:
            raise ValueError("interval must be positive")
        done = 0
        while runs is None or done < runs:
            await sleep(interval)
            done += 1
            try:
                report = await anyio.to_thread.run_sync(self.run)
            except Exception:
                logger.exception("retention run failed")
                continue
            logger.info("retention run: %s", report.to_dict())
