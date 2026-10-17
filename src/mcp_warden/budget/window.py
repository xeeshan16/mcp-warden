"""Fixed calendar windows in UTC."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from mcp_warden.policy import BudgetWindow


def window_bounds(window: BudgetWindow, now: datetime) -> tuple[datetime, datetime]:
    """The ``[start, end)`` of the window containing ``now``, both in UTC."""
    if now.tzinfo is None:
        raise ValueError("naive datetimes are ambiguous; pass a timezone-aware value")
    now = now.astimezone(UTC)
    if window is BudgetWindow.HOUR:
        start = now.replace(minute=0, second=0, microsecond=0)
        return start, start + timedelta(hours=1)
    day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if window is BudgetWindow.DAY:
        return day, day + timedelta(days=1)
    if window is BudgetWindow.WEEK:
        start = day - timedelta(days=day.weekday())
        return start, start + timedelta(days=7)
    start = day.replace(day=1)
    end = (
        start.replace(year=start.year + 1, month=1)
        if start.month == 12
        else start.replace(month=start.month + 1)
    )
    return start, end
