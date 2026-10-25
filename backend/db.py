from collections.abc import Generator
import os

from dotenv import load_dotenv
from sqlalchemy.engine import URL
from sqlmodel import Session, SQLModel, create_engine

load_dotenv()


def database_url_from_environment() -> URL:
    host = os.getenv("DB_HOSTNAME")
    username = os.getenv("DB_USERNAME")
    password = os.getenv("DB_PASSWORD")
    database = os.getenv("DB_NAME")
    missing = [
        name
        for name, value in (
            ("DB_HOSTNAME", host),
            ("DB_USERNAME", username),
            ("DB_PASSWORD", password),
            ("DB_NAME", database),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(
            "PostgreSQL configuration is incomplete; set " + ", ".join(missing)
        )
    try:
        port = int(os.getenv("DB_PORT", "5432"))
    except ValueError as exc:
        raise RuntimeError("DB_PORT must be a valid port number") from exc
    if not 1 <= port <= 65535:
        raise RuntimeError("DB_PORT must be between 1 and 65535")
    return URL.create(
        "postgresql+psycopg2",
        username=username,
        password=password,
        host=host,
        port=port,
        database=database,
        query={"sslmode": os.getenv("DB_SSLMODE", "require")},
    )


DATABASE_URL = database_url_from_environment()
engine = create_engine(DATABASE_URL, pool_pre_ping=True)


def init_db() -> None:
    SQLModel.metadata.create_all(engine)


def get_db() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session
