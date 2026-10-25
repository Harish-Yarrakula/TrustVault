import pytest


@pytest.fixture(autouse=True)
def use_isolated_test_secret(monkeypatch):
    monkeypatch.setenv(
        "SECRET_KEY",
        "pytest-only-secret-key-that-is-long-enough",
    )
