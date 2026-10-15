"""Agents and their API keys, backed by SQLAlchemy.

The store is synchronous; the async authenticator runs it in a worker thread.
Methods return frozen snapshots rather than ORM objects so callers never touch
a detached or half-loaded row.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from mcp_warden.db.models import Agent, ApiKey
from mcp_warden.identity.keys import DUMMY_DIGEST, generate_key, parse_prefix, verify_key

Clock = Callable[[], datetime]

# Same alphabet the policy and the dry-run API accept for agent ids.
AGENT_NAME = re.compile(r"^[A-Za-z0-9_.:@-]{1,100}$")
RESERVED_AGENT_NAMES = frozenset({"anonymous"})
MAX_LABEL = 100
MAX_DESCRIPTION = 500
# ``last_used_at`` is refreshed at most this often, so a busy agent does not
# turn every tool call into a write.
LAST_USED_RESOLUTION = timedelta(minutes=1)


def utcnow() -> datetime:
    return datetime.now(UTC)


class IdentityError(ValueError):
    """A request to the identity store that cannot be satisfied."""


class AgentExistsError(IdentityError):
    pass


class AgentNotFoundError(IdentityError):
    pass


class KeyNotFoundError(IdentityError):
    pass


@dataclass(frozen=True, slots=True)
class AgentInfo:
    name: str
    description: str
    disabled: bool
    created_at: datetime


@dataclass(frozen=True, slots=True)
class KeyInfo:
    agent: str
    prefix: str
    label: str
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None

    def status(self, now: datetime) -> str:
        if self.revoked_at is not None:
            return "revoked"
        if self.expires_at is not None and self.expires_at <= now:
            return "expired"
        return "active"


@dataclass(frozen=True, slots=True)
class IssuedKey:
    """A freshly issued key. ``plaintext`` is shown once and never stored."""

    info: KeyInfo
    plaintext: str

    def __repr__(self) -> str:
        return f"IssuedKey(info={self.info!r})"


def _agent_info(row: Agent) -> AgentInfo:
    return AgentInfo(row.name, row.description, row.disabled, row.created_at)


def _key_info(row: ApiKey, agent: str) -> KeyInfo:
    return KeyInfo(
        agent,
        row.prefix,
        row.label,
        row.created_at,
        row.expires_at,
        row.revoked_at,
        row.last_used_at,
    )


class IdentityStore:
    def __init__(self, sessions: sessionmaker[Session], clock: Clock = utcnow) -> None:
        self._sessions = sessions
        self._clock = clock

    # -- agents -----------------------------------------------------------

    def create_agent(self, name: str, description: str = "") -> AgentInfo:
        if not AGENT_NAME.fullmatch(name):
            raise IdentityError(f"invalid agent name: {name!r}")
        if name in RESERVED_AGENT_NAMES:
            raise IdentityError(f"agent name is reserved: {name!r}")
        if len(description) > MAX_DESCRIPTION:
            raise IdentityError(f"description longer than {MAX_DESCRIPTION} characters")
        row = Agent(name=name, description=description, disabled=False, created_at=self._clock())
        try:
            with self._sessions.begin() as session:
                session.add(row)
        except IntegrityError as exc:
            raise AgentExistsError(f"agent already exists: {name}") from exc
        return _agent_info(row)

    def get_agent(self, name: str) -> AgentInfo:
        with self._sessions() as session:
            return _agent_info(self._agent(session, name))

    def list_agents(self) -> list[AgentInfo]:
        with self._sessions() as session:
            rows = session.scalars(select(Agent).order_by(Agent.name))
            return [_agent_info(r) for r in rows]

    def set_disabled(self, name: str, disabled: bool) -> AgentInfo:
        with self._sessions.begin() as session:
            row = self._agent(session, name)
            row.disabled = disabled
            return _agent_info(row)

    # -- keys -------------------------------------------------------------

    def issue_key(
        self, agent: str, label: str = "", expires_in: timedelta | None = None
    ) -> IssuedKey:
        if len(label) > MAX_LABEL:
            raise IdentityError(f"label longer than {MAX_LABEL} characters")
        if expires_in is not None and expires_in <= timedelta(0):
            raise IdentityError("expiry must be in the future")
        now = self._clock()
        generated = generate_key()
        with self._sessions.begin() as session:
            owner = self._agent(session, agent)
            row = ApiKey(
                agent_id=owner.id,
                prefix=generated.prefix,
                key_hash=generated.digest,
                label=label,
                created_at=now,
                expires_at=now + expires_in if expires_in is not None else None,
            )
            session.add(row)
        return IssuedKey(_key_info(row, agent), generated.plaintext)

    def list_keys(self, agent: str) -> list[KeyInfo]:
        with self._sessions() as session:
            owner = self._agent(session, agent)
            rows = session.scalars(
                select(ApiKey).where(ApiKey.agent_id == owner.id).order_by(ApiKey.id)
            )
            return [_key_info(r, agent) for r in rows]

    def revoke_key(self, prefix: str) -> KeyInfo:
        """Revoke a key by prefix. Revoking twice keeps the first timestamp."""
        with self._sessions.begin() as session:
            row = session.scalar(select(ApiKey).where(ApiKey.prefix == prefix))
            if row is None:
                raise KeyNotFoundError(f"no key with prefix {prefix}")
            if row.revoked_at is None:
                row.revoked_at = self._clock()
            return _key_info(row, row.agent.name)

    # -- authentication ---------------------------------------------------

    def authenticate(self, candidate: str) -> str | None:
        """Return the agent name for a valid key, or ``None``.

        Every failure (malformed, unknown, wrong secret, revoked, expired,
        agent disabled) looks the same to the caller, so a probe learns
        nothing about which keys or agents exist.
        """
        prefix = parse_prefix(candidate)
        if prefix is None:
            return None
        now = self._clock()
        with self._sessions() as session:
            row = session.scalar(select(ApiKey).where(ApiKey.prefix == prefix))
            if row is None:
                verify_key(candidate, DUMMY_DIGEST)
                return None
            if not verify_key(candidate, row.key_hash):
                return None
            if row.revoked_at is not None:
                return None
            if row.expires_at is not None and row.expires_at <= now:
                return None
            agent = row.agent
            if agent.disabled:
                return None
            if row.last_used_at is None or now - row.last_used_at >= LAST_USED_RESOLUTION:
                row.last_used_at = now
                session.commit()
            return agent.name

    @staticmethod
    def _agent(session: Session, name: str) -> Agent:
        row = session.scalar(select(Agent).where(Agent.name == name))
        if row is None:
            raise AgentNotFoundError(f"no such agent: {name}")
        return row
