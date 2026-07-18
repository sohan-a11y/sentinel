"""Small, additive schema upgrades for the standalone Sentinel MVP.

Production deployments should move these revisions to Alembic before running
multiple workers. This module only handles the safe, backwards-compatible
upgrade from the pre-control-plane schema: it creates new tables through
SQLAlchemy metadata and adds nullable ScanSession bindings if an old database
already exists.
"""
from __future__ import annotations

from sqlalchemy import Engine, inspect, text


def upgrade_schema(engine: Engine) -> None:
    """Apply the control-plane's additive legacy-column upgrade once.

    SQLAlchemy metadata creates missing tables but never adds columns to
    existing tables. Both SQLite and PostgreSQL accept these nullable columns;
    leaving them nullable keeps historical reports readable.
    """
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())
    if "scan_sessions" in table_names:
        existing_columns = {column["name"] for column in inspector.get_columns("scan_sessions")}
        statements: list[str] = []
        if "contract_id" not in existing_columns:
            statements.append("ALTER TABLE scan_sessions ADD COLUMN contract_id INTEGER")
        if "permitted_action_tier" not in existing_columns:
            # The persisted enum values are tier_a and tier_b. A portable varchar
            # avoids an engine-specific enum-type migration in this MVP.
            statements.append("ALTER TABLE scan_sessions ADD COLUMN permitted_action_tier VARCHAR(6)")

        with engine.begin() as connection:
            for statement in statements:
                connection.execute(text(statement))
            connection.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_scan_sessions_contract_id "
                    "ON scan_sessions (contract_id)"
                )
            )

    # ``scan_contracts`` was introduced after the earliest schema, so it may
    # be absent on an old database.  When it exists, add the privacy-preserving
    # customer authorization digest without rewriting historical contracts.
    refreshed = inspect(engine)
    if "scan_contracts" not in refreshed.get_table_names():
        return
    contract_columns = {column["name"] for column in refreshed.get_columns("scan_contracts")}
    if "customer_authorization_reference_hash" not in contract_columns:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE scan_contracts "
                    "ADD COLUMN customer_authorization_reference_hash VARCHAR(64)"
                )
            )
