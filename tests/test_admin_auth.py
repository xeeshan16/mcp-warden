"""Admin authentication: named and shared tokens, and who an approval is recorded under."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from conftest import FakeClock
from mcp_warden.admin import SHARED_ADMIN, AdminAuthenticator, AdminPrincipal
from mcp_warden.config import Settings
from test_approval_stores import T0
from test_proxy_approval import RecordingUpstream, gateway, session, ticket

ALICE = "alice-token-0123456789"
BOB = "bob-token-0123456789ab"
SHARED = "shared-token-0123456789"


def bearer(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


def test_named_tokens_resolve_to_their_owner() -> None:
    admins = AdminAuthenticator({"alice": ALICE, "bob": BOB}, SHARED)
    assert admins.enabled
    assert admins.names == ["alice", "bob", SHARED_ADMIN]
    assert admins.authenticate(ALICE) == AdminPrincipal("alice", shared=False)
    assert admins.authenticate(BOB) == AdminPrincipal("bob", shared=False)
    assert admins.authenticate(SHARED) == AdminPrincipal(SHARED_ADMIN, shared=True)


@pytest.mark.parametrize("supplied", [None, "", "nope", ALICE[:-1], ALICE + "x", ALICE.upper()])
def test_anything_else_is_rejected(supplied: str | None) -> None:
    assert AdminAuthenticator({"alice": ALICE}).authenticate(supplied) is None


def test_no_tokens_means_disabled() -> None:
    admins = AdminAuthenticator({})
    assert not admins.enabled
    assert admins.authenticate(ALICE) is None


@pytest.mark.parametrize(
    ("named", "shared", "message"),
    [
        ({"alice": "short"}, None, "shorter than 16"),
        ({"al ice": ALICE}, None, "invalid admin name"),
        ({"": ALICE}, None, "invalid admin name"),
        ({SHARED_ADMIN: ALICE}, None, "reserved"),
        ({"alice": ALICE, "bob": ALICE}, None, "distinct"),
        ({"alice": ALICE}, ALICE, "distinct"),
    ],
)
def test_bad_configurations_are_refused(
    named: dict[str, str], shared: str | None, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        AdminAuthenticator(named, shared)


def test_settings_read_named_tokens_from_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WARDEN_ADMIN_TOKENS", f'{{"alice": "{ALICE}", "bob": "{BOB}"}}')
    admins = Settings().admin_authenticator()
    assert admins.authenticate(BOB) == AdminPrincipal("bob", shared=False)
    # Tokens stay out of reprs and logs.
    assert ALICE not in repr(Settings())


def test_settings_refuse_bad_named_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WARDEN_ADMIN_TOKENS", '{"alice": "short"}')
    with pytest.raises(ValueError, match="WARDEN_ADMIN_TOKENS"):
        Settings()
    monkeypatch.setenv("WARDEN_ADMIN_TOKENS", f'{{"alice": "{ALICE}"}}')
    with pytest.raises(ValueError, match="distinct"):
        Settings(admin_token=ALICE)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(T0)


@pytest.fixture
def upstream() -> RecordingUpstream:
    return RecordingUpstream()


def _pending(client: TestClient, **arguments: str) -> str:
    approval_id: str = ticket(client, session(client), **arguments).json()["error"]["data"][
        "approval_id"
    ]
    return approval_id


def test_a_named_admin_decides_as_themselves(upstream: RecordingUpstream, clock: FakeClock) -> None:
    with gateway(upstream, clock, admin_token=None, admin_tokens={"alice": ALICE}) as client:
        approval_id = _pending(client)
        resp = client.post(f"/v1/approvals/{approval_id}/approve", json={}, headers=bearer(ALICE))
        assert resp.status_code == 200
        assert resp.json()["decided_by"] == "alice"


def test_a_named_admin_cannot_sign_as_someone_else(
    upstream: RecordingUpstream, clock: FakeClock
) -> None:
    tokens = {"alice": ALICE, "bob": BOB}
    with gateway(upstream, clock, admin_token=None, admin_tokens=tokens) as client:
        approval_id = _pending(client)
        url = f"/v1/approvals/{approval_id}/deny"
        forged = client.post(url, json={"reviewer": "bob"}, headers=bearer(ALICE))
        assert forged.status_code == 403
        own = client.post(url, json={"reviewer": "bob"}, headers=bearer(BOB))
        assert own.status_code == 200
        assert own.json()["decided_by"] == "bob"


def test_the_shared_token_names_the_reviewer_or_is_recorded_as_admin(
    upstream: RecordingUpstream, clock: FakeClock
) -> None:
    with gateway(upstream, clock, admin_token=SHARED) as client:
        first = _pending(client)
        named = client.post(
            f"/v1/approvals/{first}/deny", json={"reviewer": "carol"}, headers=bearer(SHARED)
        )
        assert named.json()["decided_by"] == "carol"
        second = _pending(client, title="Another outage", priority="urgent")
        anonymous = client.post(f"/v1/approvals/{second}/deny", json={}, headers=bearer(SHARED))
        assert anonymous.json()["decided_by"] == SHARED_ADMIN
