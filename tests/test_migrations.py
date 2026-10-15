from __future__ import annotations

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Engine, inspect

from mcp_warden.db import (
    Base,
    DatabaseNotReadyError,
    ensure_schema_current,
    make_engine,
    upgrade,
)
from mcp_warden.db.migrate import current_revision, head_revision


def test_empty_database_is_not_ready(db_url: str) -> None:
    engine = make_engine(db_url)
    with pytest.raises(DatabaseNotReadyError, match="mcp-warden db upgrade"):
        ensure_schema_current(engine)
    engine.dispose()


def test_upgrade_reaches_head(db_engine: Engine) -> None:
    assert current_revision(db_engine) == head_revision()
    ensure_schema_current(db_engine)
    tables = set(inspect(db_engine).get_table_names())
    assert {"agents", "api_keys", "alembic_version"} <= tables


def test_migrations_match_the_models(db_engine: Engine) -> None:
    with db_engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []


def test_upgrade_is_idempotent(db_engine: Engine) -> None:
    upgrade(db_engine)
    assert current_revision(db_engine) == head_revision()


def test_downgrade_to_base(db_engine: Engine) -> None:
    from alembic import command

    from mcp_warden.db.migrate import alembic_config

    command.downgrade(alembic_config(db_engine), "base")
    assert current_revision(db_engine) is None
    assert set(inspect(db_engine).get_table_names()) <= {"alembic_version"}
    with pytest.raises(DatabaseNotReadyError):
        ensure_schema_current(db_engine)


def test_in_memory_sqlite_shares_one_connection() -> None:
    engine = make_engine("sqlite://")
    upgrade(engine)
    ensure_schema_current(engine)
    engine.dispose()
