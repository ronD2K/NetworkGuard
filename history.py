
import json
from pathlib import Path
from datetime import datetime

HISTORY_FILE = Path(__file__).resolve().parent / "scan_history.json"


def save_history(devices, new_devices):
    history = []

    if HISTORY_FILE.exists():
        try:
            with HISTORY_FILE.open("r", encoding="utf-8") as file:
                history = json.load(file)
        except (json.JSONDecodeError, OSError):
            print("Could not load scan history.")
            return

    record = {
        "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
        "total_devices": len(devices),
        "devices": devices,
        "new_devices": new_devices
    }

    history.append(record)

    with HISTORY_FILE.open("w", encoding="utf-8") as file:
        json.dump(history, file, indent=4)

    print("Scan history saved!")


def show_history():
    if not HISTORY_FILE.exists():
        print("No scan history found.")
        return

    try:
        with HISTORY_FILE.open("r", encoding="utf-8") as file:
            history = json.load(file)
    except (json.JSONDecodeError, OSError):
        print("Could not read scan history.")
        return

    print("\n--- Scan History ---")

    for record in history:
        print(f"\nTime: {record['timestamp']}")
        print(f"Hosts found: {record['total_devices']}")
        print(f"New IPs: {len(record['new_devices'])}")
