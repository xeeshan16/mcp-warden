from __future__ import annotations

import pytest

from mcp_warden.identity.keys import (
    DUMMY_DIGEST,
    PREFIX_HEX_CHARS,
    digest_key,
    generate_key,
    parse_prefix,
    verify_key,
)


def test_generated_key_shape() -> None:
    key = generate_key()
    scheme, prefix, secret = key.plaintext.split("_", 2)
    assert scheme == "mcpw"
    assert prefix == key.prefix
    assert len(prefix) == PREFIX_HEX_CHARS
    assert len(secret) == 43
    assert key.digest == digest_key(key.plaintext)
    assert len(key.digest) == 64
    assert parse_prefix(key.plaintext) == key.prefix


def test_keys_are_unique() -> None:
    keys = {generate_key().plaintext for _ in range(200)}
    assert len(keys) == 200


def test_repr_never_shows_the_secret() -> None:
    key = generate_key()
    assert key.plaintext not in repr(key)
    assert key.prefix in repr(key)


def test_verify() -> None:
    key = generate_key()
    assert verify_key(key.plaintext, key.digest)
    other = generate_key()
    assert not verify_key(other.plaintext, key.digest)
    assert not verify_key(key.plaintext, DUMMY_DIGEST)


@pytest.mark.parametrize(
    "candidate",
    [
        "",
        "mcpw_",
        "Bearer mcpw_0123456789ab_" + "A" * 43,
        "mcpw_0123456789AB_" + "A" * 43,  # prefix must be lower-case hex
        "mcpw_0123456789ab_" + "A" * 42,
        "mcpw_0123456789ab_" + "A" * 44,
        "mcpw_0123456789ab_" + "A" * 42 + "=",
        "sk_0123456789ab_" + "A" * 43,
        "mcpw_0123456789ab_" + "A" * 43 + "\n",
    ],
)
def test_parse_prefix_rejects_malformed(candidate: str) -> None:
    assert parse_prefix(candidate) is None
