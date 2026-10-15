"""Agent identity: API keys, the identity store and request authentication."""

from mcp_warden.identity.auth import (
    AGENT_HEADER,
    ANONYMOUS_AGENT,
    ApiKeyAuthenticator,
    AuthenticationError,
    Authenticator,
    TrustedHeaderAuthenticator,
    bearer_token,
)
from mcp_warden.identity.store import (
    AgentExistsError,
    AgentInfo,
    AgentNotFoundError,
    IdentityError,
    IdentityStore,
    IssuedKey,
    KeyInfo,
    KeyNotFoundError,
)

__all__ = [
    "AGENT_HEADER",
    "ANONYMOUS_AGENT",
    "AgentExistsError",
    "AgentInfo",
    "AgentNotFoundError",
    "ApiKeyAuthenticator",
    "AuthenticationError",
    "Authenticator",
    "IdentityError",
    "IdentityStore",
    "IssuedKey",
    "KeyInfo",
    "KeyNotFoundError",
    "TrustedHeaderAuthenticator",
    "bearer_token",
]
