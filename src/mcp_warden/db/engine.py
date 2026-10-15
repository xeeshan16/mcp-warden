"""Engine and session factories.

SQLite is supported for development and fast tests; PostgreSQL (``psycopg``,
installed with the ``postgres`` extra) is the production target. SQLite needs
foreign keys switched on per connection for ``ON DELETE CASCADE`` to work.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


def make_engine(url: str, **kwargs: Any) -> Engine:
    """Create an engine; in-memory SQLite gets a single shared connection."""
    options: dict[str, Any] = {"future": True, **kwargs}
    if url.startswith("sqlite"):
        options.setdefault("connect_args", {"check_same_thread": False})
        if url in ("sqlite://", "sqlite:///:memory:"):
            options.setdefault("poolclass", StaticPool)
    else:
        options.setdefault("pool_pre_ping", True)
    engine = create_engine(url, **options)
    if engine.dialect.name == "sqlite":
        event.listen(engine, "connect", _enable_sqlite_foreign_keys)
    return engine


def _enable_sqlite_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def make_sessionmaker(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)
