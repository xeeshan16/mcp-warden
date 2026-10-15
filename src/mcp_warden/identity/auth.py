"""Turning an HTTP request into an agent identity.

Two authenticators exist:

* :class:`ApiKeyAuthenticator` (the default): the agent sends
  ``Authorization: Bearer mcpw_...``; the key is checked against the identity
  store and resolves to the agent's name.
* :class:`TrustedHeaderAuthenticator`: the agent name is taken from
  ``X-Warden-Agent``. Only safe behind a proxy that authenticates callers and
  sets the header itself; meant for local development and tests.

Both return the agent name the policy is evaluated against, or raise
:class:`AuthenticationError`, which the proxy turns into an HTTP error carrying
a JSON-RPC error body.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Protocol

import anyio.to_thread

from mcp_warden.identity.store import IdentityStore
from mcp_warden.jsonrpc import ErrorCode, JsonRpcError

AGENT_HEADER = "x-warden-agent"
ANONYMOUS_AGENT = "anonymous"
_AGENT_ID = re.compile(r"^[A-Za-z0-9_.:@-]{1,100}$")
_MAX_AUTHORIZATION = 512
WWW_AUTHENTICATE = 'Bearer realm="mcp-warden"'


class AuthenticationError(JsonRpcError):
    """A request whose caller could not be identified."""

    def __init__(self, status: int, code: ErrorCode, message: str) -> None:
        super().__init__(code, message)
        self.status = status
        self.headers: dict[str, str] = (
            {"www-authenticate": WWW_AUTHENTICATE} if status == 401 else {}
        )


class Authenticator(Protocol):
    async def authenticate(self, headers: Mapping[str, str]) -> str: ...


def _lowered(headers: Mapping[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def bearer_token(headers: Mapping[str, str]) -> str | None:
    raw = _lowered(headers).get("authorization")
    if raw is None or len(raw) > _MAX_AUTHORIZATION:
        return None
    scheme, _, token = raw.strip().partition(" ")
    if scheme.lower() != "bearer":
        return None
    token = token.strip()
    return token or None


class ApiKeyAuthenticator:
    def __init__(self, store: IdentityStore) -> None:
        self.store = store

    async def authenticate(self, headers: Mapping[str, str]) -> str:
        token = bearer_token(headers)
        if token is None:
            raise AuthenticationError(401, ErrorCode.UNAUTHENTICATED, "missing bearer API key")
        agent = await anyio.to_thread.run_sync(self.store.authenticate, token)
        if agent is None:
            raise AuthenticationError(
                401, ErrorCode.UNAUTHENTICATED, "invalid, expired or revoked API key"
            )
        return agent


class TrustedHeaderAuthenticator:
    """Read the agent from ``X-Warden-Agent``; a missing header is ``anonymous``."""

    async def authenticate(self, headers: Mapping[str, str]) -> str:
        raw = _lowered(headers).get(AGENT_HEADER)
        if raw is None:
            return ANONYMOUS_AGENT
        agent = raw.strip()
        if not _AGENT_ID.fullmatch(agent):
            raise AuthenticationError(
                400, ErrorCode.INVALID_REQUEST, f"invalid {AGENT_HEADER} header"
            )
        return agent
