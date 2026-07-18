from __future__ import annotations

from sqlalchemy import create_engine, inspect, text

from sentinel.db.migrations import upgrade_schema


def test_control_plane_upgrade_adds_bindings_to_a_legacy_scan_sessions_table():
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE scan_sessions ("
                "id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL, status VARCHAR(16) NOT NULL)"
            )
        )

    upgrade_schema(engine)

    columns = {column["name"] for column in inspect(engine).get_columns("scan_sessions")}
    assert {"contract_id", "permitted_action_tier"} <= columns

    # It is intentionally idempotent; application startup can safely call it.
    upgrade_schema(engine)


def test_control_plane_upgrade_adds_a_privacy_preserving_authorization_digest_to_contracts():
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE scan_sessions ("
                "id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL, status VARCHAR(16) NOT NULL)"
            )
        )
        connection.execute(
            text(
                "CREATE TABLE scan_contracts ("
                "id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL, approved_by VARCHAR(255) NOT NULL)"
            )
        )

    upgrade_schema(engine)

    columns = {column["name"] for column in inspect(engine).get_columns("scan_contracts")}
    assert "customer_authorization_reference_hash" in columns


def test_authorization_digest_upgrade_does_not_depend_on_a_legacy_scan_sessions_table():
    """Each additive migration must run when its own table exists."""
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE scan_contracts ("
                "id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL, approved_by VARCHAR(255) NOT NULL)"
            )
        )

    upgrade_schema(engine)

    columns = {column["name"] for column in inspect(engine).get_columns("scan_contracts")}
    assert "customer_authorization_reference_hash" in columns
