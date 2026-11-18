
from monitor import detect_new_devices


def test_detect_new_ip():
    previous = [
        {"ip": "10.0.0.1", "mac": None}
    ]

    current = [
        {"ip": "10.0.0.1", "mac": None},
        {"ip": "10.0.0.20", "mac": None}
    ]

    result = detect_new_devices(current, previous)

    assert len(result) == 1
    assert result[0]["ip"] == "10.0.0.20"


def test_no_new_devices():
    previous = [
        {"ip": "10.0.0.10", "mac": None}
    ]

    current = [
        {"ip": "10.0.0.10", "mac": None}
    ]

    result = detect_new_devices(current, previous)

    assert result == []


def test_same_mac_different_ip():
    previous = [
        {
            "ip": "10.0.0.10",
            "mac": "AA:BB:CC:DD:EE:FF"
        }
    ]

    current = [
        {
            "ip": "10.0.0.50",
            "mac": "AA:BB:CC:DD:EE:FF"
        }
    ]

    result = detect_new_devices(current, previous)

    assert result == []


def test_completely_new_device():
    previous = [
        {
            "ip": "10.0.0.10",
            "mac": "AA:BB:CC:DD:EE:FF"
        }
    ]

    current = [
        {
            "ip": "10.0.0.20",
            "mac": "11:22:33:44:55:66"
        }
    ]

    result = detect_new_devices(current, previous)

    assert len(result) == 1
