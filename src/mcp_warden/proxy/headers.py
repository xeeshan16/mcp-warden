"""Header hygiene for the MCP endpoint.

Only two of the agent's headers ever reach an upstream: ``Mcp-Session-Id``
and ``MCP-Protocol-Version``. Both are checked here before anything is
forwarded:

* each may appear at most once, so the gateway and the upstream can never
  read different values from one request;
* a session id must be 1 to 1024 visible ASCII characters (0x21 to 0x7E),
  as MCP requires; the same check applies to session ids an upstream hands
  out, before they are passed back to the agent;
* a protocol version must look like an MCP revision (``YYYY-MM-DD``). The
  gateway compares revisions to decide whether batches are allowed, so a
  free-form value must not take part in that comparison.

``Origin`` is checked as the MCP transport specification asks, against
DNS-rebinding attacks from a browser: a request that carries one must name an
allowed origin. Agents that are not browsers send no ``Origin`` and are not
affected.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping

SESSION_HEADER = "mcp-session-id"
PROTOCOL_HEADER = "mcp-protocol-version"
FORWARDED_HEADERS: tuple[str, ...] = (SESSION_HEADER, PROTOCOL_HEADER)

_SESSION_ID = re.compile(r"[\x21-\x7e]{1,1024}")
_PROTOCOL_VERSION = re.compile(r"\d{4}-\d{2}-\d{2}")


class HeaderError(ValueError):
    """A forwarded header is repeated or malformed."""


def valid_session_id(value: str) -> bool:
    return _SESSION_ID.fullmatch(value) is not None


def valid_protocol_version(value: str) -> bool:
    return _PROTOCOL_VERSION.fullmatch(value) is not None


_VALIDATORS = {SESSION_HEADER: valid_session_id, PROTOCOL_HEADER: valid_protocol_version}


def forwarded_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """The agent's headers that cross the gateway, validated.

    ``headers`` may be a multi-dict (Starlette's ``Headers``) whose ``items()``
    yields a repeated header once per occurrence.
    """
    found: dict[str, str] = {}
    for key, value in headers.items():
        name = key.lower()
        if name not in _VALIDATORS:
            continue
        if name in found:
            raise HeaderError(f"{name} must not be repeated")
        if not _VALIDATORS[name](value):
            raise HeaderError(f"invalid {name} header")
        found[name] = value
    return {name: found[name] for name in FORWARDED_HEADERS if name in found}


def origin_allowed(origin: str | None, allowed: Collection[str]) -> bool:
    """Whether a request's ``Origin`` (if any) is one of ``allowed``.

    Origins are compared exactly after lower-casing; ``null`` (sandboxed
    frames, files) is only allowed if listed.
    """
    if origin is None:
        return True
    return origin.strip().lower() in {o.lower() for o in allowed}
