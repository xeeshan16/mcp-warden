"""Runtime configuration, read from ``WARDEN_*`` environment variables."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from mcp_warden.jsonrpc.parser import ParseLimits


class AuthMode(StrEnum):
    # Per-agent API keys checked against the database (the default).
    API_KEY = "api-key"
    # Trust ``X-Warden-Agent`` as set by an authenticating proxy in front of
    # the gateway. For local development and tests only.
    TRUSTED_HEADER = "trusted-header"


class RateLimitStore(StrEnum):
    # Buckets in process memory: exact, but per gateway instance.
    MEMORY = "memory"
    # Buckets in the database: shared by every instance using it.
    DATABASE = "database"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="WARDEN_", env_file=".env", extra="ignore")

    policy_path: Path = Field(
        default=Path("examples/policy.yaml"),
        description="Path to the YAML policy file.",
    )
    upstreams_path: Path | None = Field(
        default=Path("examples/upstreams.yaml"),
        description="Path to the YAML file listing upstream MCP servers.",
    )
    database_url: str = Field(
        default="sqlite:///./mcp-warden.db",
        description="SQLAlchemy URL, e.g. postgresql+psycopg://user:pass@host/db.",
    )
    auth_mode: AuthMode = Field(default=AuthMode.API_KEY, description="How agents are identified.")
    rate_limit_store: RateLimitStore = Field(
        default=RateLimitStore.MEMORY,
        description="Where token buckets for the policy's rate_limits are kept.",
    )
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    log_level: str = "info"

    max_message_bytes: int = Field(
        default=1_000_000, ge=1, description="Largest JSON-RPC payload accepted, in bytes."
    )
    max_json_depth: int = Field(default=64, ge=1, description="Deepest JSON nesting accepted.")
    max_batch_size: int = Field(default=50, ge=1, description="Most messages in one batch.")
    max_upstream_response_bytes: int = Field(
        default=10_000_000, ge=1, description="Largest upstream reply accepted, in bytes."
    )

    def parse_limits(self, *, allow_batch: bool = True) -> ParseLimits:
        return ParseLimits(
            max_bytes=self.max_message_bytes,
            max_depth=self.max_json_depth,
            max_batch_size=self.max_batch_size,
            allow_batch=allow_batch,
        )
