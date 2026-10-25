"""Initialize the SQLModel schema in the configured PostgreSQL database."""
import server as _server  # Registers all application SQLModel tables.
from db import init_db


if __name__ == "__main__":
    init_db()
    print("TrustVault schema initialized")
