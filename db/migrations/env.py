"""
Alembic migration environment.

DATABASE_URL is read from the environment (via config.py) so credentials
are never stored in version control.  The models' Base.metadata is imported
here so `alembic revision --autogenerate` can diff the ORM against the DB.
"""

import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, inspect, pool, text

# Make sure the project root is on sys.path so `from db.models import Base`
# resolves correctly regardless of where alembic is invoked from.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from config import DATABASE_URL  # noqa: E402
from db.models import Base       # noqa: E402  — imports all mapped classes
# db.models bottom-imports shared_corpus.models, so the shared tier is already
# registered on Base.metadata above; import it explicitly too so the dependency
# is obvious and autogenerate always sees the shared-tier tables.
import shared_corpus.models  # noqa: E402,F401

# Alembic Config object (gives access to alembic.ini values)
config = context.config

# Override sqlalchemy.url with the value from the environment.
# This means alembic.ini never needs a real connection string.
if DATABASE_URL:
    config.set_main_option("sqlalchemy.url", DATABASE_URL)

# Set up Python logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# This is what autogenerate inspects to build migration scripts.
target_metadata = Base.metadata


def _ensure_version_column_capacity(connection) -> None:
    """Keep legacy PostgreSQL Alembic tables able to store current revision IDs.

    The initial Alembic table used VARCHAR(32), but later revision identifiers
    are longer than 32 characters.  Widen the metadata column before Alembic
    writes the next revision; this touches only migration bookkeeping, never
    application data.
    """
    if connection.dialect.name != "postgresql":
        return
    inspector = inspect(connection)
    if "alembic_version" not in inspector.get_table_names():
        return
    version_column = next(
        (c for c in inspector.get_columns("alembic_version") if c["name"] == "version_num"),
        None,
    )
    current_length = getattr(version_column.get("type"), "length", None) if version_column else None
    if current_length is not None and current_length < 255:
        connection.execute(
            text(
                "ALTER TABLE alembic_version "
                "ALTER COLUMN version_num TYPE VARCHAR(255)"
            )
        )


def run_migrations_offline() -> None:
    """
    Run migrations without a live DB connection.
    Emits SQL to stdout — useful for review or for DBAs who apply migrations manually.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Run migrations against a live DB connection.
    This is the normal path for `alembic upgrade head`.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,  # no pooling needed for one-shot migration runs
    )
    with connectable.begin() as connection:
        _ensure_version_column_capacity(connection)
        # ``_ensure_version_column_capacity`` issues a read (``inspect``) and
        # possibly an ALTER. Under SQLAlchemy 2.0 that autobegins a transaction
        # on the connection. If it is left open, alembic's
        # ``context.begin_transaction()`` below sees an existing transaction,
        # treats itself as a no-op, and never commits — so ``with connection``
        # exits and SA 2.0 rolls back EVERY migration plus the version bump
        # (silent success, nothing persisted; PostgreSQL-only, hence invisible
        # on the SQLite test path). Commit here to persist the capacity fix and
        # hand alembic a clean, transaction-free connection to manage.
        if connection.in_transaction():
            connection.commit()
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,        # detect column type changes in autogenerate
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
