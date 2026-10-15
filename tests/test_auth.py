from __future__ import annotations

import pytest

from mcp_warden.identity import (
    ApiKeyAuthenticator,
    AuthenticationError,
    IdentityStore,
    TrustedHeaderAuthenticator,
    bearer_token,
)
from mcp_warden.jsonrpc import ErrorCode

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({"Authorization": "Bearer abc"}, "abc"),
        ({"authorization": "bearer   abc  "}, "abc"),
        ({"AUTHORIZATION": "BEARER abc"}, "abc"),
        ({}, None),
        ({"authorization": "Basic dXNlcjpwYXNz"}, None),
        ({"authorization": "Bearer"}, None),
        ({"authorization": "Bearer "}, None),
        ({"authorization": "Bearer " + "a" * 600}, None),
    ],
)
def test_bearer_token(headers: dict[str, str], expected: str | None) -> None:
    assert bearer_token(headers) == expected


async def test_api_key_authenticator(store: IdentityStore) -> None:
    store.create_agent("bot")
    issued = store.issue_key("bot")
    auth = ApiKeyAuthenticator(store)
    assert await auth.authenticate({"authorization": f"Bearer {issued.plaintext}"}) == "bot"


@pytest.mark.parametrize(
    ("headers", "message"),
    [
        ({}, "missing bearer API key"),
        ({"authorization": "Basic abc"}, "missing bearer API key"),
        ({"authorization": "Bearer mcpw_nope"}, "invalid, expired or revoked API key"),
    ],
)
async def test_api_key_authenticator_rejects(
    store: IdentityStore, headers: dict[str, str], message: str
) -> None:
    with pytest.raises(AuthenticationError) as info:
        await ApiKeyAuthenticator(store).authenticate(headers)
    assert info.value.status == 401
    assert info.value.code == ErrorCode.UNAUTHENTICATED
    assert info.value.message == message
    assert info.value.headers == {"www-authenticate": 'Bearer realm="mcp-warden"'}


async def test_trusted_header_authenticator() -> None:
    auth = TrustedHeaderAuthenticator()
    assert await auth.authenticate({}) == "anonymous"
    assert await auth.authenticate({"X-Warden-Agent": " support-bot "}) == "support-bot"
    with pytest.raises(AuthenticationError) as info:
        await auth.authenticate({"x-warden-agent": "not valid!"})
    assert info.value.status == 400
    assert info.value.code == ErrorCode.INVALID_REQUEST
    assert info.value.headers == {}
