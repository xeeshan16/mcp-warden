"""Alembic integration without an ``alembic.ini``.

The migration scripts ship inside the package, so ``mcp-warden db upgrade``
works from an installed wheel. The gateway itself never migrates on startup;
it checks that the schema is at the latest revision and refuses to start
otherwise, so a forgotten upgrade is a clear error rather than a 500 on the
first authenticated request.
"""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Engine

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


class DatabaseNotReadyError(RuntimeError):
    """The database schema is missing or not at the latest revision."""


def alembic_config(engine: Engine) -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    config.attributes["engine"] = engine
    return config


def head_revision() -> str:
    script = ScriptDirectory(str(MIGRATIONS_DIR))
    head = script.get_current_head()
    if head is None:  # pragma: no cover - the package always ships migrations
        raise RuntimeError("no migrations found")
    return head


def current_revision(engine: Engine) -> str | None:
    with engine.connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()


def upgrade(engine: Engine, revision: str = "head") -> None:
    command.upgrade(alembic_config(engine), revision)


def ensure_schema_current(engine: Engine) -> None:
    current = current_revision(engine)
    head = head_revision()
    if current != head:
        found = current or "an empty database"
        raise DatabaseNotReadyError(
            f"database schema is at {found}, expected {head}; run `mcp-warden db upgrade`"
        )
