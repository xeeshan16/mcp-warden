"""Alembic environment.

The engine normally comes from :func:`mcp_warden.db.migrate.alembic_config`.
When Alembic is run directly (``uv run alembic ...`` with the repository's
``alembic.ini``, e.g. to autogenerate a revision), the URL comes from
``WARDEN_DATABASE_URL`` via the gateway settings.
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import Engine

from mcp_warden.db.engine import make_engine
from mcp_warden.db.models import Base

config = context.config
target_metadata = Base.metadata


def _engine() -> Engine:
    engine = config.attributes.get("engine")
    if isinstance(engine, Engine):
        return engine
    from mcp_warden.config import Settings

    return make_engine(Settings().database_url)


def run_migrations_offline() -> None:
    from mcp_warden.config import Settings

    context.configure(
        url=Settings().database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    with _engine().connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # Batch mode lets ALTERs work on SQLite too.
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()
        connection.commit()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
