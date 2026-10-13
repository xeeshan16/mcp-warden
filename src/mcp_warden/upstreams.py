"""Registry of upstream MCP servers the gateway forwards to.

Upstreams are declared in YAML::

    version: 1
    servers:
      - name: github
        url: https://mcp.example.internal/github/mcp
        timeout_seconds: 30
        headers_from_env:
          Authorization: GITHUB_MCP_AUTHORIZATION

Credentials for an upstream never live in the file: ``headers_from_env`` maps
an outgoing header to the *name* of an environment variable, resolved once at
startup so that a missing secret stops the gateway instead of failing the
first call.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, ValidationError, model_validator

MAX_UPSTREAMS_BYTES = 256_000

_SERVER_NAME = r"^[A-Za-z0-9_.-]{1,100}$"
_HEADER_NAME = r"^[A-Za-z0-9-]{1,100}$"
_ENV_NAME = r"^[A-Za-z_][A-Za-z0-9_]{0,200}$"

# Headers the gateway owns on the upstream leg; configuring them would either
# break the protocol framing or let config smuggle in a client session.
_RESERVED_HEADERS = frozenset(
    {
        "accept",
        "content-type",
        "content-length",
        "host",
        "connection",
        "transfer-encoding",
        "mcp-session-id",
        "mcp-protocol-version",
    }
)


class UpstreamError(ValueError):
    """Raised when the upstream registry cannot be loaded or validated."""


class UpstreamSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=_SERVER_NAME)
    url: AnyHttpUrl
    description: str | None = Field(default=None, max_length=500)
    timeout_seconds: float = Field(default=30.0, gt=0, le=600)
    connect_timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    headers_from_env: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_headers(self) -> UpstreamSpec:
        for header, env_name in self.headers_from_env.items():
            if not re.fullmatch(_HEADER_NAME, header):
                raise ValueError(f"invalid header name {header!r}")
            if header.lower() in _RESERVED_HEADERS:
                raise ValueError(f"header {header!r} is managed by the gateway")
            if not re.fullmatch(_ENV_NAME, env_name):
                raise ValueError(f"invalid environment variable name {env_name!r}")
        return self


class UpstreamsDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1]
    servers: list[UpstreamSpec] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_names(self) -> UpstreamsDocument:
        seen: set[str] = set()
        for server in self.servers:
            if server.name in seen:
                raise ValueError(f"duplicate server name {server.name!r}")
            seen.add(server.name)
        return self


@dataclass(frozen=True, slots=True)
class Upstream:
    """A resolved upstream: configuration plus the static headers to send."""

    name: str
    url: str
    timeout_seconds: float
    connect_timeout_seconds: float
    headers: Mapping[str, str] = field(default_factory=dict, repr=False)

    def __repr__(self) -> str:  # never print resolved credentials
        return f"Upstream(name={self.name!r}, url={self.url!r})"


class UpstreamRegistry:
    """Immutable name → upstream lookup."""

    def __init__(self, upstreams: list[Upstream] | None = None) -> None:
        self._by_name = {u.name: u for u in upstreams or []}
        if len(self._by_name) != len(upstreams or []):
            raise UpstreamError("duplicate upstream names")

    def get(self, name: str) -> Upstream | None:
        return self._by_name.get(name)

    def names(self) -> list[str]:
        return sorted(self._by_name)

    def __iter__(self) -> Iterator[Upstream]:
        return iter(self._by_name[name] for name in self.names())

    def __len__(self) -> int:
        return len(self._by_name)


def _format(exc: ValidationError) -> str:
    parts = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"]) or "<root>"
        parts.append(f"{loc}: {err['msg']}")
    return "; ".join(parts)


def resolve(document: UpstreamsDocument, env: Mapping[str, str]) -> UpstreamRegistry:
    upstreams = []
    for spec in document.servers:
        headers: dict[str, str] = {}
        for header, env_name in spec.headers_from_env.items():
            value = env.get(env_name)
            if not value:
                raise UpstreamError(
                    f"server {spec.name!r}: environment variable {env_name} "
                    f"(for header {header}) is not set"
                )
            headers[header] = value
        upstreams.append(
            Upstream(
                name=spec.name,
                url=str(spec.url),
                timeout_seconds=spec.timeout_seconds,
                connect_timeout_seconds=spec.connect_timeout_seconds,
                headers=headers,
            )
        )
    return UpstreamRegistry(upstreams)


def parse_upstreams(data: Any, env: Mapping[str, str] | None = None) -> UpstreamRegistry:
    if not isinstance(data, dict):
        raise UpstreamError("upstreams document must be a mapping at the top level")
    try:
        document = UpstreamsDocument.model_validate(data)
    except ValidationError as exc:
        raise UpstreamError(f"invalid upstreams: {_format(exc)}") from exc
    return resolve(document, os.environ if env is None else env)


def load_upstreams(text: str, env: Mapping[str, str] | None = None) -> UpstreamRegistry:
    if len(text.encode("utf-8")) > MAX_UPSTREAMS_BYTES:
        raise UpstreamError(f"upstreams document exceeds {MAX_UPSTREAMS_BYTES} bytes")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise UpstreamError(f"upstreams file is not valid YAML: {exc}") from exc
    return parse_upstreams(data, env)


def load_upstreams_file(path: str | Path, env: Mapping[str, str] | None = None) -> UpstreamRegistry:
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise UpstreamError(f"cannot read upstreams file {file_path}: {exc.strerror}") from exc
    return load_upstreams(text, env)
