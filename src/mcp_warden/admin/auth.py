"""Who is calling the admin API.

Two kinds of credentials are accepted, both as ``Authorization: Bearer ...``:

* named tokens from ``WARDEN_ADMIN_TOKENS`` (a JSON object of name to token):
  each person or system gets its own token, and the name is what approval
  decisions and logs record, so a reviewer cannot sign as someone else;
* the shared ``WARDEN_ADMIN_TOKEN``: one token for everyone, kept for small
  setups; its holder is called ``admin`` and may name the reviewer per decision.

With neither configured the admin API is switched off. Tokens are compared as
SHA-256 digests with :func:`hmac.compare_digest`, against every configured
token without stopping at the first match, so timing reveals neither which
tokens exist nor how much of one was guessed.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping
from dataclasses import dataclass

SHARED_ADMIN = "admin"
ADMIN_NAME = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
MIN_TOKEN_LENGTH = 16


@dataclass(frozen=True, slots=True)
class AdminPrincipal:
    """An authenticated admin caller."""

    name: str
    # True for the shared token, whose holder is not individually known.
    shared: bool


def _digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


class AdminAuthenticator:
    def __init__(self, named: Mapping[str, str], shared: str | None = None) -> None:
        for name, token in named.items():
            if not ADMIN_NAME.fullmatch(name):
                raise ValueError(f"invalid admin name: {name!r}")
            if name == SHARED_ADMIN:
                raise ValueError(f"admin name {SHARED_ADMIN!r} is reserved for the shared token")
            if len(token) < MIN_TOKEN_LENGTH:
                raise ValueError(f"admin token for {name} is shorter than {MIN_TOKEN_LENGTH}")
        tokens = [*named.values(), *([shared] if shared is not None else [])]
        if len(set(tokens)) != len(tokens):
            raise ValueError("admin tokens must be distinct")
        self._entries: list[tuple[bytes, AdminPrincipal]] = [
            (_digest(token), AdminPrincipal(name, shared=False)) for name, token in named.items()
        ]
        if shared is not None:
            self._entries.append((_digest(shared), AdminPrincipal(SHARED_ADMIN, shared=True)))

    @property
    def enabled(self) -> bool:
        return bool(self._entries)

    @property
    def names(self) -> list[str]:
        return [principal.name for _, principal in self._entries]

    def authenticate(self, supplied: str | None) -> AdminPrincipal | None:
        """The principal a bearer token belongs to, or ``None``."""
        if supplied is None or not self._entries:
            return None
        candidate = _digest(supplied)
        found = None
        for digest, principal in self._entries:
            if hmac.compare_digest(candidate, digest) and found is None:
                found = principal
        return found
