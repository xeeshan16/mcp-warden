"""Reloading the policy file into a running gateway.

A reload reads the file, validates it completely and only then swaps it into
the shared :class:`PolicyEngine`. A file that does not parse or validate never
replaces a working policy: the gateway keeps enforcing the last good version
and reports the error, so a typo during an edit cannot open or close
everything at once.

Files are compared by SHA-256 of their content rather than modification time,
so a ``touch`` is not a reload and an edit within the same second is not
missed.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import anyio.to_thread

from mcp_warden.policy.engine import PolicyEngine
from mcp_warden.policy.loader import MAX_POLICY_BYTES, PolicyError, load_policy
from mcp_warden.policy.model import Policy

logger = logging.getLogger(__name__)

Clock = Callable[[], datetime]


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _iso(ts: datetime | None) -> str | None:
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if ts is not None else None


@dataclass(frozen=True, slots=True)
class SectionChanges:
    """Entries of one policy section, by id, that a reload added, removed or edited."""

    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    changed: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.added or self.removed or self.changed)

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "added": list(self.added),
            "removed": list(self.removed),
            "changed": list(self.changed),
        }


def _section(old: Sequence[Any], new: Sequence[Any]) -> SectionChanges:
    before = {entry.id: entry for entry in old}
    after = {entry.id: entry for entry in new}
    return SectionChanges(
        added=tuple(i for i in after if i not in before),
        removed=tuple(i for i in before if i not in after),
        changed=tuple(i for i in after if i in before and after[i] != before[i]),
    )


@dataclass(frozen=True, slots=True)
class PolicyChanges:
    rules: SectionChanges
    rate_limits: SectionChanges
    budgets: SectionChanges
    default_changed: bool

    @classmethod
    def between(cls, old: Policy, new: Policy) -> PolicyChanges:
        return cls(
            rules=_section(old.rules, new.rules),
            rate_limits=_section(old.rate_limits, new.rate_limits),
            budgets=_section(old.budgets, new.budgets),
            default_changed=old.default is not new.default,
        )

    def __bool__(self) -> bool:
        return bool(self.rules or self.rate_limits or self.budgets or self.default_changed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rules": self.rules.to_dict(),
            "rate_limits": self.rate_limits.to_dict(),
            "budgets": self.budgets.to_dict(),
            "default_changed": self.default_changed,
        }

    def describe(self) -> str:
        parts = []
        for name, section in (
            ("rules", self.rules),
            ("rate limits", self.rate_limits),
            ("budgets", self.budgets),
        ):
            counts = [
                f"{len(ids)} {verb}"
                for verb, ids in (
                    ("added", section.added),
                    ("removed", section.removed),
                    ("changed", section.changed),
                )
                if ids
            ]
            if counts:
                parts.append(f"{name}: {', '.join(counts)}")
        if self.default_changed:
            parts.append("default changed")
        return "; ".join(parts) or "no effective change"


@dataclass(frozen=True, slots=True)
class ReloadResult:
    # False when the file's content was identical to the policy in force.
    changed: bool
    sha256: str
    changes: PolicyChanges | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "changed": self.changed,
            "sha256": self.sha256,
            "changes": self.changes.to_dict() if self.changes is not None else None,
        }


@dataclass(slots=True)
class _State:
    sha256: str | None
    loaded_at: datetime | None
    last_checked_at: datetime | None = None
    last_error: str | None = None
    reloads: int = 0
    failures: int = 0


def _read(path: Path) -> tuple[str, str]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {path}: {exc.strerror}") from exc
    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyError(f"policy document exceeds {MAX_POLICY_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyError(f"policy file {path} is not UTF-8") from exc
    return text, hashlib.sha256(raw).hexdigest()


class PolicyReloader:
    """Owns the policy file of a running gateway and swaps new versions in."""

    def __init__(
        self,
        engine: PolicyEngine,
        path: Path,
        *,
        sha256: str | None = None,
        clock: Clock = _utcnow,
    ) -> None:
        self.engine = engine
        self.path = path
        self._clock = clock
        self._lock = threading.Lock()
        self._state = _State(sha256=sha256, loaded_at=clock() if sha256 is not None else None)

    @classmethod
    def from_file(cls, path: Path, *, clock: Clock = _utcnow) -> PolicyReloader:
        """Load the initial policy; a broken file raises :class:`PolicyError`."""
        text, digest = _read(path)
        return cls(PolicyEngine(load_policy(text)), path, sha256=digest, clock=clock)

    @property
    def sha256(self) -> str | None:
        return self._state.sha256

    @property
    def reloads(self) -> int:
        """Reloads that swapped in a new policy."""
        return self._state.reloads

    @property
    def failed_reloads(self) -> int:
        return self._state.failures

    @property
    def last_error(self) -> str | None:
        """Why the latest reload attempt failed; ``None`` once one succeeds."""
        return self._state.last_error

    @property
    def loaded_at(self) -> datetime | None:
        return self._state.loaded_at

    def reload(self) -> ReloadResult:
        """Read, validate and apply the file.

        Raises :class:`PolicyError` (and keeps the current policy) when the file
        cannot be read or is invalid. Identical content is a no-op.
        """
        with self._lock:
            now = self._clock()
            self._state.last_checked_at = now
            try:
                text, digest = _read(self.path)
                if digest == self._state.sha256:
                    self._state.last_error = None
                    return ReloadResult(changed=False, sha256=digest)
                policy = load_policy(text)
            except PolicyError as exc:
                self._state.last_error = str(exc)
                self._state.failures += 1
                raise
            previous = self.engine.replace(policy)
            self._state.sha256 = digest
            self._state.loaded_at = now
            self._state.last_error = None
            self._state.reloads += 1
        changes = PolicyChanges.between(previous, policy)
        logger.info("policy reloaded from %s (%s): %s", self.path, digest[:12], changes.describe())
        return ReloadResult(changed=True, sha256=digest, changes=changes)

    def check(self) -> ReloadResult | None:
        """Reload if the file changed; log instead of raising. For the watcher."""
        try:
            return self.reload()
        except PolicyError as exc:
            logger.error("policy reload failed, keeping the current policy: %s", exc)
            return None

    async def run_periodically(self, interval_seconds: float) -> None:
        """Poll the file every ``interval_seconds`` until cancelled."""
        while True:
            await asyncio.sleep(interval_seconds)
            await anyio.to_thread.run_sync(self.check)

    def status(self) -> dict[str, Any]:
        state = self._state
        return {
            "path": str(self.path),
            "sha256": state.sha256,
            "loaded_at": _iso(state.loaded_at),
            "last_checked_at": _iso(state.last_checked_at),
            "last_error": state.last_error,
            "reloads": state.reloads,
            "failed_reloads": state.failures,
        }
