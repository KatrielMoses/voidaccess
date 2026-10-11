"""
tests/test_migration_persistence.py — P3-HARDEN / DRIFT-2 regression guard.

DRIFT-2 was "migration reported success but committed nothing": under SQLAlchemy
2.0 autobegin, ``alembic upgrade head`` could roll back every migration on
PostgreSQL while returning cleanly — invisible on the SQLite test path (which
autocommits DDL), so a naive "run upgrade, no error" test never catches it.

This guard catches that CLASS of failure the only way it can be caught: run the
migrations on **PostgreSQL**, then assert the migrated tables are visible from a
**brand-new connection** (a connection that did not run the migration). If a
migration ran inside a transaction that was never committed, the fresh connection
sees nothing and this fails.

How it runs (CI-with-PG or operator check)
------------------------------------------
It skips unless a Postgres DSN is provided, so the default suite (SQLite) is
unaffected. To run it::

    VOIDACCESS_PG_TEST_URL=postgresql://user:pass@localhost:5432/voidaccess \\
        pytest tests/test_migration_persistence.py

The connecting role needs CREATE on the target database (the guard runs inside a
throwaway schema and drops it afterward — no CREATEDB privilege required).
"""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import create_engine, inspect, text

_PG_URL = os.getenv("VOIDACCESS_PG_TEST_URL", "")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Tables introduced by P2/P3 migrations — their presence on a fresh connection is
# the persistence proof.
_MIGRATED_TABLES = ("discovered_onions", "jobs", "page_snapshots")


@pytest.mark.skipif(
    not _PG_URL.startswith("postgresql"),
    reason="set VOIDACCESS_PG_TEST_URL=postgresql://... to run the PG migration-persistence guard",
)
def test_migrations_persist_across_a_fresh_connection():
    schema = "harden_guard_" + uuid.uuid4().hex[:12]
    sep = "&" if "?" in _PG_URL else "?"
    # Route all unqualified DDL (and alembic_version) into the throwaway schema.
    scoped_url = f"{_PG_URL}{sep}options=-csearch_path%3D{schema}"

    admin = create_engine(_PG_URL)
    with admin.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))

    try:
        # --- run `alembic upgrade head` against the scoped Postgres URL --------
        from alembic import command
        from alembic.config import Config
        import config as app_config

        cfg = Config(os.path.join(_REPO_ROOT, "alembic.ini"))
        prev_env = os.environ.get("DATABASE_URL")
        prev_cfg = getattr(app_config, "DATABASE_URL", None)
        os.environ["DATABASE_URL"] = scoped_url
        app_config.DATABASE_URL = scoped_url  # env.py reads config.DATABASE_URL
        try:
            command.upgrade(cfg, "head")
        finally:
            if prev_env is None:
                os.environ.pop("DATABASE_URL", None)
            else:
                os.environ["DATABASE_URL"] = prev_env
            app_config.DATABASE_URL = prev_cfg

        # --- THE guard: a fresh connection/engine must see the migrated tables --
        fresh = create_engine(scoped_url)
        try:
            names = set(inspect(fresh).get_table_names(schema=schema))
            missing = [t for t in _MIGRATED_TABLES if t not in names]
            assert not missing, (
                f"migrations reported success but these tables are not visible on a "
                f"fresh connection (DRIFT-2 non-commit regression): {missing}; "
                f"present={sorted(names)}"
            )
            # Actually read from one — persistence, not just catalog reflection.
            with fresh.connect() as conn:
                conn.execute(text(f'SELECT 1 FROM "{schema}".discovered_onions LIMIT 0'))
        finally:
            fresh.dispose()
    finally:
        with admin.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()
