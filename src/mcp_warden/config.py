"""Runtime configuration, read from ``WARDEN_*`` environment variables."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from mcp_warden.admin.auth import AdminAuthenticator
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


class UsageStoreKind(StrEnum):
    # Budget usage in process memory: lost on restart, per gateway instance.
    MEMORY = "memory"
    # Budget usage in the database ledger: durable and shared.
    DATABASE = "database"


class ApprovalStoreKind(StrEnum):
    # Requests in process memory: decided through the admin API, lost on restart.
    MEMORY = "memory"
    # Requests in the database: shared by gateways, decidable from the CLI.
    DATABASE = "database"


class AuditStoreKind(StrEnum):
    # Events in a bounded ring in process memory: recent history only.
    MEMORY = "memory"
    # Events in the database: durable, shared, queryable from the CLI.
    DATABASE = "database"
    # No audit log at all.
    OFF = "off"


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
    usage_store: UsageStoreKind = Field(
        default=UsageStoreKind.MEMORY,
        description="Where usage for the policy's budgets is booked.",
    )
    chars_per_token: float = Field(
        default=4.0,
        gt=0,
        le=100,
        description="Characters per token for the default token estimator.",
    )
    approval_store: ApprovalStoreKind = Field(
        default=ApprovalStoreKind.MEMORY,
        description="Where approval requests for require_approval calls are kept.",
    )
    approval_ttl_seconds: int = Field(
        default=900, ge=1, le=7 * 86400, description="How long a request waits for a reviewer."
    )
    approval_decision_ttl_seconds: int = Field(
        default=600,
        ge=1,
        le=7 * 86400,
        description="How long an approval can be used, and a denial is repeated.",
    )
    approval_wait_seconds: float = Field(
        default=0,
        ge=0,
        le=60,
        description="How long a call waits in the gateway for a decision before -32002.",
    )
    approval_max_pending_per_agent: int = Field(
        default=20, ge=1, description="Most requests one agent may have waiting at once."
    )
    approval_retry_after_seconds: int = Field(
        default=5, ge=1, description="Retry-After suggested to agents waiting for a decision."
    )
    admin_token: SecretStr | None = Field(
        default=None,
        description="Shared bearer token for the admin API; its holder is called 'admin'.",
    )
    admin_tokens: dict[str, SecretStr] = Field(
        default_factory=dict,
        description='Named admin tokens as a JSON object, e.g. {"alice": "..."}.',
    )
    policy_reload_interval_seconds: float = Field(
        default=0,
        ge=0,
        description="Check the policy file for changes this often and reload it; 0 disables.",
    )
    audit_store: AuditStoreKind = Field(
        default=AuditStoreKind.MEMORY, description="Where audit events are written."
    )
    audit_hash_key: SecretStr | None = Field(
        default=None,
        description="Key for HMAC digests of tool arguments in the audit log; unset: SHA-256.",
    )
    audit_memory_max_events: int = Field(
        default=10_000, ge=1, description="Most events the in-memory audit store keeps."
    )
    retention_days: float = Field(
        default=30,
        gt=0,
        le=3650,
        description="How long audit events, finished approvals and ended budget windows are kept.",
    )
    retention_interval_seconds: float = Field(
        default=0,
        ge=0,
        description="Run the retention job in the gateway this often; 0 leaves it to the CLI.",
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

    @field_validator("admin_token")
    @classmethod
    def _strong_admin_token(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value()) < 16:
            raise ValueError("WARDEN_ADMIN_TOKEN must be at least 16 characters")
        return value

    @model_validator(mode="after")
    def _valid_admin_tokens(self) -> Settings:
        # Built once here so a bad name, a short or a reused token stops startup.
        try:
            self.admin_authenticator()
        except ValueError as exc:
            raise ValueError(f"WARDEN_ADMIN_TOKENS: {exc}") from exc
        return self

    def admin_authenticator(self) -> AdminAuthenticator:
        shared = self.admin_token.get_secret_value() if self.admin_token is not None else None
        return AdminAuthenticator(
            {name: token.get_secret_value() for name, token in self.admin_tokens.items()},
            shared,
        )

    @field_validator("audit_hash_key")
    @classmethod
    def _strong_audit_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value().encode()) < 16:
            raise ValueError("WARDEN_AUDIT_HASH_KEY must be at least 16 bytes")
        return value

    def parse_limits(self, *, allow_batch: bool = True) -> ParseLimits:
        return ParseLimits(
            max_bytes=self.max_message_bytes,
            max_depth=self.max_json_depth,
            max_batch_size=self.max_batch_size,
            allow_batch=allow_batch,
        )
