import sys

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from db import engine


def main() -> int:
    try:
        with engine.connect() as connection:
            database_name = connection.execute(
                text("SELECT current_database()")
            ).scalar_one()
    except SQLAlchemyError as exc:
        print(f"PostgreSQL connection failed: {exc.orig}", file=sys.stderr)
        return 1

    print(f"PostgreSQL connection successful (database: {database_name}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())



    