"""Runtime configuration, read from ``WARDEN_*`` environment variables."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from mcp_warden.jsonrpc.parser import ParseLimits


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="WARDEN_", env_file=".env", extra="ignore")

    policy_path: Path = Field(
        default=Path("examples/policy.yaml"),
        description="Path to the YAML policy file.",
    )
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    log_level: str = "info"

    max_message_bytes: int = Field(
        default=1_000_000, ge=1, description="Largest JSON-RPC payload accepted, in bytes."
    )
    max_json_depth: int = Field(default=64, ge=1, description="Deepest JSON nesting accepted.")
    max_batch_size: int = Field(default=50, ge=1, description="Most messages in one batch.")

    def parse_limits(self, *, allow_batch: bool = True) -> ParseLimits:
        return ParseLimits(
            max_bytes=self.max_message_bytes,
            max_depth=self.max_json_depth,
            max_batch_size=self.max_batch_size,
            allow_batch=allow_batch,
        )
