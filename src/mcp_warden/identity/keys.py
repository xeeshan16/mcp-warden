"""API key format, generation and verification.

A key looks like ``mcpw_<prefix>_<secret>``:

* ``mcpw_`` makes leaked keys easy to recognise (and to add to secret scanners);
* ``prefix`` is 12 random hex characters, stored in clear and used to find the
  key row and to identify a key in listings and logs;
* ``secret`` is 32 random bytes, URL-safe base64 encoded (43 characters).

Only ``sha256(full key)`` is stored. A slow password hash (bcrypt, argon2) buys
nothing here: the secret has 256 bits of entropy, so the digest cannot be
brute-forced, and a fast hash keeps per-request authentication cheap.
Digests are compared with :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass

KEY_SCHEME = "mcpw"
PREFIX_HEX_CHARS = 12
SECRET_BYTES = 32

_KEY_RE = re.compile(rf"^{KEY_SCHEME}_([0-9a-f]{{{PREFIX_HEX_CHARS}}})_([A-Za-z0-9_-]{{43}})$")


@dataclass(frozen=True, slots=True)
class GeneratedKey:
    prefix: str
    plaintext: str
    digest: str

    def __repr__(self) -> str:
        # Never let the plaintext end up in a log line or traceback.
        return f"GeneratedKey(prefix={self.prefix!r})"


def digest_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("ascii")).hexdigest()


def generate_key() -> GeneratedKey:
    prefix = secrets.token_hex(PREFIX_HEX_CHARS // 2)
    plaintext = f"{KEY_SCHEME}_{prefix}_{secrets.token_urlsafe(SECRET_BYTES)}"
    return GeneratedKey(prefix, plaintext, digest_key(plaintext))


def parse_prefix(candidate: str) -> str | None:
    """Return the key's prefix if ``candidate`` is shaped like a key, else ``None``."""
    match = _KEY_RE.fullmatch(candidate)
    return match.group(1) if match else None


def verify_key(candidate: str, stored_digest: str) -> bool:
    return hmac.compare_digest(digest_key(candidate), stored_digest)


# Compared against when no key row matches, so an unknown prefix costs the same
# hashing work as a wrong secret.
DUMMY_DIGEST = digest_key(f"{KEY_SCHEME}_{'0' * PREFIX_HEX_CHARS}_{'A' * 43}")
