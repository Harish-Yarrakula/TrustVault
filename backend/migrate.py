"""Initialize the fixed SQLModel schema for the demo database."""
import server  # Registers all application SQLModel tables, including token revocations.
from db import init_db


if __name__ == "__main__":
    init_db()
    print("TrustVault schema initialized")
