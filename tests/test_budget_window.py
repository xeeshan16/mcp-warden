from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from mcp_warden.budget import window_bounds
from mcp_warden.policy import BudgetWindow

NOW = datetime(2026, 10, 17, 13, 45, 12, 999, tzinfo=UTC)  # a Saturday


def utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=UTC)


@pytest.mark.parametrize(
    ("window", "start", "end"),
    [
        (BudgetWindow.HOUR, utc(2026, 10, 17, 13), utc(2026, 10, 17, 14)),
        (BudgetWindow.DAY, utc(2026, 10, 17), utc(2026, 10, 18)),
        (BudgetWindow.WEEK, utc(2026, 10, 12), utc(2026, 10, 19)),
        (BudgetWindow.MONTH, utc(2026, 10, 1), utc(2026, 11, 1)),
    ],
)
def test_bounds(window: BudgetWindow, start: datetime, end: datetime) -> None:
    assert window_bounds(window, NOW) == (start, end)


def test_month_rolls_over_the_year() -> None:
    assert window_bounds(BudgetWindow.MONTH, utc(2026, 12, 31, 23, 59)) == (
        utc(2026, 12, 1),
        utc(2027, 1, 1),
    )


def test_week_starting_on_monday_is_its_own_start() -> None:
    assert window_bounds(BudgetWindow.WEEK, utc(2026, 10, 19)) == (
        utc(2026, 10, 19),
        utc(2026, 10, 26),
    )


def test_end_is_exclusive() -> None:
    assert window_bounds(BudgetWindow.HOUR, utc(2026, 10, 17, 14))[0] == utc(2026, 10, 17, 14)


def test_other_timezones_are_converted_to_utc() -> None:
    # 01:30 on the 18th in UTC+5 is 20:30 on the 17th in UTC.
    local = datetime(2026, 10, 18, 1, 30, tzinfo=timezone(timedelta(hours=5)))
    assert window_bounds(BudgetWindow.DAY, local) == (utc(2026, 10, 17), utc(2026, 10, 18))


def test_naive_datetimes_are_rejected() -> None:
    with pytest.raises(ValueError, match="naive"):
        window_bounds(BudgetWindow.DAY, datetime(2026, 10, 17))
