from types import SimpleNamespace

import pytest

import server
from db import database_url_from_environment


class FakeSession:
    def __init__(self):
        self.statements = []
        self.commits = 0

    def exec(self, statement):
        self.statements.append(str(statement))

    def commit(self):
        self.commits += 1


def test_database_url_uses_required_postgres_environment(monkeypatch):
    monkeypatch.setenv("DB_HOSTNAME", "db.example.test")
    monkeypatch.setenv("DB_PORT", "5432")
    monkeypatch.setenv("DB_USERNAME", "trustvault_user")
    monkeypatch.setenv("DB_PASSWORD", "test-password")
    monkeypatch.setenv("DB_NAME", "trustvault")
    monkeypatch.delenv("DB_SSLMODE", raising=False)

    url = database_url_from_environment()

    assert url.drivername == "postgresql+psycopg2"
    assert url.host == "db.example.test"
    assert url.port == 5432
    assert url.username == "trustvault_user"
    assert url.password == "test-password"
    assert url.database == "trustvault"
    assert url.query["sslmode"] == "require"


@pytest.mark.parametrize(
    "name",
    ["DB_HOSTNAME", "DB_USERNAME", "DB_PASSWORD", "DB_NAME"],
)
def test_database_url_requires_postgres_environment(monkeypatch, name):
    for variable in ("DB_HOSTNAME", "DB_USERNAME", "DB_PASSWORD", "DB_NAME"):
        monkeypatch.setenv(variable, "configured")
    monkeypatch.delenv(name)

    with pytest.raises(RuntimeError, match=name):
        database_url_from_environment()


def test_database_url_rejects_invalid_port(monkeypatch):
    monkeypatch.setenv("DB_HOSTNAME", "db.example.test")
    monkeypatch.setenv("DB_USERNAME", "trustvault_user")
    monkeypatch.setenv("DB_PASSWORD", "test-password")
    monkeypatch.setenv("DB_NAME", "trustvault")
    monkeypatch.setenv("DB_PORT", "not-a-port")

    with pytest.raises(RuntimeError, match="DB_PORT"):
        database_url_from_environment()


def test_development_secret_fallback_meets_minimum_length(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("SECRET_KEY", raising=False)

    assert len(server.config_secret()) >= 32


@pytest.mark.parametrize("secret", ["", "change-me", "<paste the openssl output>"])
def test_production_rejects_missing_or_placeholder_secret(monkeypatch, secret):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SECRET_KEY", secret)

    with pytest.raises(RuntimeError, match="SECRET_KEY must be configured"):
        server.config_secret()


def test_enum_migration_adds_postgres_labels_and_commits(monkeypatch):
    monkeypatch.setattr(
        server,
        "engine",
        SimpleNamespace(dialect=SimpleNamespace(name="postgresql")),
    )
    db = FakeSession()

    server.ensure_postgres_enum_values(db)

    assert db.statements == [
        "ALTER TYPE userrole ADD VALUE IF NOT EXISTS 'EXTERNAL_CLIENT'",
        "ALTER TYPE permissionlevel ADD VALUE IF NOT EXISTS 'READ'",
        "ALTER TYPE permissionlevel ADD VALUE IF NOT EXISTS 'WRITE'",
    ] + [
        f"ALTER TYPE auditaction ADD VALUE IF NOT EXISTS '{action.value}'"
        for action in server.AuditAction
    ]
    assert db.commits == 1


def test_audit_event_migration_adds_model_columns_and_index(monkeypatch):
    monkeypatch.setattr(
        server,
        "engine",
        SimpleNamespace(dialect=SimpleNamespace(name="postgresql")),
    )
    monkeypatch.setattr(
        server,
        "inspect",
        lambda _engine: SimpleNamespace(get_columns=lambda _table: []),
    )
    db = FakeSession()

    server.ensure_audit_event_columns(db)

    assert db.statements == [
        "ALTER TABLE audit_events ADD COLUMN request_id VARCHAR(100)",
        "ALTER TABLE audit_events ADD COLUMN user_agent VARCHAR(512)",
        "CREATE INDEX IF NOT EXISTS ix_audit_events_request_id ON audit_events (request_id)",
    ]
    assert db.commits == 1


def test_audit_event_migration_adds_missing_sqlite_columns(monkeypatch):
    from sqlalchemy import create_engine
    from sqlmodel import Session

    test_engine = create_engine("sqlite://")
    monkeypatch.setattr(server, "engine", test_engine)
    with test_engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE audit_events (id INTEGER PRIMARY KEY)")

    with Session(test_engine) as db:
        server.ensure_audit_event_columns(db)

    columns = {column["name"] for column in server.inspect(test_engine).get_columns("audit_events")}
    assert {"id", "request_id", "user_agent"} <= columns
    indexes = server.inspect(test_engine).get_indexes("audit_events")
    assert any(
        index["name"] == "ix_audit_events_request_id"
        for index in indexes
    )


def test_document_schema_migration_adds_column_and_indexes(monkeypatch):
    from sqlalchemy import create_engine, text
    from sqlmodel import Session

    test_engine = create_engine("sqlite://")
    monkeypatch.setattr(server, "engine", test_engine)
    with test_engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE documents ("
            "id INTEGER PRIMARY KEY, "
            "company_id VARCHAR(36), "
            "content_sha256 VARCHAR(64), "
            "category VARCHAR(100), "
            "upload_verified_at TIMESTAMP)"
        )

    with Session(test_engine) as db:
        server.ensure_document_schema(db)
        server.ensure_document_schema(db)

    with test_engine.connect() as connection:
        column = next(
            column
            for column in server.inspect(test_engine).get_columns("documents")
            if column["name"] == "content_type"
        )
        document_columns = {
            column["name"]
            for column in server.inspect(test_engine).get_columns("documents")
        }
        connection.execute(text("INSERT INTO documents DEFAULT VALUES"))
        value = connection.execute(
            text("SELECT content_type FROM documents")
        ).scalar_one()
        indexes = {
            index["name"]
            for index in server.inspect(test_engine).get_indexes("documents")
        }

    assert str(column["type"]) == "VARCHAR(255)"
    assert column["nullable"] is False
    assert value == "application/octet-stream"
    assert {
        "ix_documents_category",
        "ix_documents_upload_verified_at",
        "ix_documents_deleted_at",
        "uq_documents_company_checksum_active",
    } <= indexes
    assert "deleted_at" in document_columns


def test_password_hash_migration_widens_legacy_column(monkeypatch):
    monkeypatch.setattr(
        server,
        "engine",
        SimpleNamespace(dialect=SimpleNamespace(name="postgresql")),
    )
    monkeypatch.setattr(
        server,
        "inspect",
        lambda _engine: SimpleNamespace(
            get_columns=lambda _table: [
                {"name": "password_hash", "type": SimpleNamespace(length=128)}
            ]
        ),
    )
    db = FakeSession()

    server.ensure_password_hash_column_width(db)

    assert db.statements == [
        "ALTER TABLE company_users ALTER COLUMN password_hash TYPE VARCHAR(255)"
    ]
    assert db.commits == 1


@pytest.mark.parametrize(
    "migration",
    [server.ensure_postgres_enum_values],
)
def test_schema_migrations_reject_non_postgres(monkeypatch, migration):
    monkeypatch.setattr(
        server,
        "engine",
        SimpleNamespace(dialect=SimpleNamespace(name="sqlite")),
    )

    with pytest.raises(RuntimeError, match="require PostgreSQL"):
        migration(FakeSession())
