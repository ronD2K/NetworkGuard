import pytest
import scanner


@pytest.fixture(autouse=True)
def use_test_network(monkeypatch):
    monkeypatch.setattr(
        scanner,
        "NETWORK",
        "192.168.56.0/24"
    )
