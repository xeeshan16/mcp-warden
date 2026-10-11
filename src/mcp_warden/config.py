"""Runtime configuration, read from ``WARDEN_*`` environment variables."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="WARDEN_", env_file=".env", extra="ignore")

    policy_path: Path = Field(
        default=Path("examples/policy.yaml"),
        description="Path to the YAML policy file.",
    )
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    log_level: str = "info"
