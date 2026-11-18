
import json
from pathlib import Path


SCAN_FILE = Path(__file__).resolve().parent / "scan_results.json"


def load_previous_scan():
    if not SCAN_FILE.exists():
        return None

    try:
        with SCAN_FILE.open("r", encoding="utf-8") as file:
            devices = json.load(file)

        if isinstance(devices, list):
            return devices

    except (json.JSONDecodeError, OSError):
        print("Could not read previous scan.")

    return None


def save_scan(devices):
    with SCAN_FILE.open("w", encoding="utf-8") as file:
        json.dump(devices, file, indent=4)


def detect_new_devices(current_devices, previous_devices):
    previous_macs = {
        device.get("mac").lower()
        for device in previous_devices
        if device.get("mac")
    }

    previous_ips = {
        device.get("ip")
        for device in previous_devices
        if device.get("ip")
    }

    new_devices = []

    for device in current_devices:
        mac = device.get("mac")
        ip = device.get("ip")

        if mac:
            if mac.lower() in previous_macs:
                continue

            # Compatibility with older IP-only scan records
            if ip in previous_ips:
                continue

        elif ip in previous_ips:
            continue

        new_devices.append(device)

    return new_devices
