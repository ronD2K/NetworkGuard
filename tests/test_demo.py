
import pytest

from demo_data import get_demo_data
from scanner import validate_network


def test_demo_has_five_devices():
    devices, history = get_demo_data()

    assert len(devices) == 5
    assert len(history) == 3


def test_demo_history_is_consistent():
    devices, history = get_demo_data()

    assert history[-1]["total_devices"] == len(devices)
    assert len(history[-1]["new_devices"]) == 1


def test_demo_uses_documentation_ips():
    devices, _ = get_demo_data()

    assert all(
        device["ip"].startswith("192.0.2.")
        for device in devices
    )


def test_live_scan_requires_configuration():
    with pytest.raises(
        ValueError,
        match="No network configured"
    ):
        validate_network("")


def test_large_network_is_rejected():
    with pytest.raises(
        ValueError,
        match="too large"
    ):
        validate_network("10.0.0.0/16")
