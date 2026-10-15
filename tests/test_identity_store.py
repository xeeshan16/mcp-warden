from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import Engine, delete, func, select

from conftest import FakeClock
from mcp_warden.db import Agent, ApiKey, make_sessionmaker
from mcp_warden.identity import (
    AgentExistsError,
    AgentNotFoundError,
    IdentityError,
    IdentityStore,
    KeyNotFoundError,
)
from mcp_warden.identity.store import LAST_USED_RESOLUTION


def test_create_and_list_agents(store: IdentityStore, clock: FakeClock) -> None:
    store.create_agent("support-bot", "answers tickets")
    store.create_agent("ci-agent")
    agents = store.list_agents()
    assert [a.name for a in agents] == ["ci-agent", "support-bot"]
    bot = store.get_agent("support-bot")
    assert bot.description == "answers tickets"
    assert not bot.disabled
    assert bot.created_at == clock.now


def test_duplicate_agent(store: IdentityStore) -> None:
    store.create_agent("bot")
    with pytest.raises(AgentExistsError):
        store.create_agent("bot")


@pytest.mark.parametrize("name", ["", "has space", "x" * 101, "semi;colon", "anonymous"])
def test_invalid_agent_names(store: IdentityStore, name: str) -> None:
    with pytest.raises(IdentityError):
        store.create_agent(name)


def test_description_length_is_limited(store: IdentityStore) -> None:
    with pytest.raises(IdentityError, match="description"):
        store.create_agent("bot", "d" * 501)


def test_unknown_agent(store: IdentityStore) -> None:
    with pytest.raises(AgentNotFoundError):
        store.get_agent("ghost")
    with pytest.raises(AgentNotFoundError):
        store.issue_key("ghost")
    with pytest.raises(AgentNotFoundError):
        store.list_keys("ghost")
    with pytest.raises(AgentNotFoundError):
        store.set_disabled("ghost", True)


def test_issue_and_authenticate(store: IdentityStore, clock: FakeClock) -> None:
    store.create_agent("bot")
    issued = store.issue_key("bot", "laptop")
    assert issued.plaintext not in repr(issued)
    assert issued.info.agent == "bot"
    assert issued.info.label == "laptop"
    assert issued.info.status(clock.now) == "active"
    assert store.authenticate(issued.plaintext) == "bot"


def test_only_the_digest_is_stored(store: IdentityStore, db_engine: Engine) -> None:
    store.create_agent("bot")
    issued = store.issue_key("bot")
    with make_sessionmaker(db_engine)() as session:
        row = session.scalars(select(ApiKey)).one()
    assert row.prefix == issued.info.prefix
    assert issued.plaintext not in (row.key_hash, row.prefix, row.label)
    secret = issued.plaintext.rsplit("_", 1)[1]
    assert secret not in row.key_hash


def test_authentication_failures_look_the_same(store: IdentityStore) -> None:
    store.create_agent("bot")
    issued = store.issue_key("bot")
    last = issued.plaintext[-1]
    wrong_secret = issued.plaintext[:-1] + ("B" if last == "A" else "A")
    unknown_prefix = "mcpw_" + "f" * 12 + issued.plaintext[17:]
    for candidate in ["", "garbage", wrong_secret, unknown_prefix, issued.plaintext.upper()]:
        assert store.authenticate(candidate) is None


def test_revoked_key(store: IdentityStore, clock: FakeClock) -> None:
    store.create_agent("bot")
    issued = store.issue_key("bot")
    revoked = store.revoke_key(issued.info.prefix)
    assert revoked.revoked_at == clock.now
    assert revoked.status(clock.now) == "revoked"
    assert store.authenticate(issued.plaintext) is None
    clock.advance(timedelta(hours=1))
    again = store.revoke_key(issued.info.prefix)
    assert again.revoked_at == revoked.revoked_at


def test_revoke_unknown_key(store: IdentityStore) -> None:
    with pytest.raises(KeyNotFoundError):
        store.revoke_key("000000000000")


def test_expiring_key(store: IdentityStore, clock: FakeClock) -> None:
    store.create_agent("bot")
    issued = store.issue_key("bot", expires_in=timedelta(days=1))
    assert issued.info.expires_at == clock.now + timedelta(days=1)
    clock.advance(timedelta(hours=23, minutes=59))
    assert store.authenticate(issued.plaintext) == "bot"
    clock.advance(timedelta(minutes=1))
    assert store.authenticate(issued.plaintext) is None
    assert store.list_keys("bot")[0].status(clock.now) == "expired"


@pytest.mark.parametrize("expires_in", [timedelta(0), timedelta(seconds=-1)])
def test_expiry_must_be_in_the_future(store: IdentityStore, expires_in: timedelta) -> None:
    store.create_agent("bot")
    with pytest.raises(IdentityError, match="future"):
        store.issue_key("bot", expires_in=expires_in)


def test_label_length_is_limited(store: IdentityStore) -> None:
    store.create_agent("bot")
    with pytest.raises(IdentityError, match="label"):
        store.issue_key("bot", "l" * 101)


def test_disabled_agent_cannot_authenticate(store: IdentityStore) -> None:
    store.create_agent("bot")
    issued = store.issue_key("bot")
    assert store.set_disabled("bot", True).disabled
    assert store.authenticate(issued.plaintext) is None
    store.set_disabled("bot", False)
    assert store.authenticate(issued.plaintext) == "bot"


def test_keys_are_independent(store: IdentityStore) -> None:
    store.create_agent("a")
    store.create_agent("b")
    key_a1 = store.issue_key("a")
    key_a2 = store.issue_key("a")
    key_b = store.issue_key("b")
    store.revoke_key(key_a1.info.prefix)
    assert store.authenticate(key_a1.plaintext) is None
    assert store.authenticate(key_a2.plaintext) == "a"
    assert store.authenticate(key_b.plaintext) == "b"
    assert [k.prefix for k in store.list_keys("a")] == [key_a1.info.prefix, key_a2.info.prefix]


def test_last_used_is_throttled(store: IdentityStore, clock: FakeClock) -> None:
    store.create_agent("bot")
    issued = store.issue_key("bot")
    assert store.list_keys("bot")[0].last_used_at is None
    first = clock.now
    store.authenticate(issued.plaintext)
    assert store.list_keys("bot")[0].last_used_at == first
    clock.advance(LAST_USED_RESOLUTION / 2)
    store.authenticate(issued.plaintext)
    assert store.list_keys("bot")[0].last_used_at == first
    clock.advance(LAST_USED_RESOLUTION)
    store.authenticate(issued.plaintext)
    assert store.list_keys("bot")[0].last_used_at == clock.now


def test_deleting_an_agent_deletes_its_keys(store: IdentityStore, db_engine: Engine) -> None:
    store.create_agent("bot")
    store.issue_key("bot")
    with make_sessionmaker(db_engine).begin() as session:
        # A bulk delete bypasses the ORM cascade, so this checks ON DELETE CASCADE.
        session.execute(delete(Agent).where(Agent.name == "bot"))
    with make_sessionmaker(db_engine)() as session:
        assert session.scalar(select(func.count()).select_from(ApiKey)) == 0


def test_naive_datetimes_are_rejected(db_engine: Engine) -> None:
    from datetime import datetime

    naive = IdentityStore(make_sessionmaker(db_engine), clock=lambda: datetime(2026, 1, 1))
    with pytest.raises(Exception, match="naive"):
        naive.create_agent("bot")
