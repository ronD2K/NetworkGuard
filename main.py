
import json
import ipaddress
from pathlib import Path

from scanner import scan_network
from monitor import (
    load_previous_scan,
    save_scan,
    detect_new_devices
)
from history import save_history, show_history


DATA_FILE = Path(__file__).resolve().parent / "devices.json"


def show_welcome():
    print("Welcome to NetworkGuard!")
    print("Home Network Security Monitor")
    print("Version 1.3")


def load_devices():
    if not DATA_FILE.exists():
        return []

    try:
        with DATA_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)

        if isinstance(data, list):
            return data

    except (json.JSONDecodeError, OSError):
        print("Could not load saved devices.")

    return []


def save_devices(devices):
    with DATA_FILE.open("w", encoding="utf-8") as file:
        json.dump(devices, file, indent=4)


def get_valid_ip():
    while True:
        ip = input("IP address: ").strip()

        try:
            ipaddress.IPv4Address(ip)
            return ip

        except ipaddress.AddressValueError:
            print("Invalid IPv4 address. Try again.")


def add_device(devices):
    name = input("Device name: ").strip()
    ip = get_valid_ip()

    while True:
        status = input("Status (Online/Offline): ").strip()

        if status.lower() in ("online", "offline"):
            status = status.capitalize()
            break

        print("Please enter Online or Offline.")

    device = {
        "name": name,
        "ip": ip,
        "status": status
    }

    devices.append(device)
    save_devices(devices)

    print("Device saved successfully!")


def show_devices(devices):
    print("\n--- Saved Devices ---")

    if not devices:
        print("No devices saved.")
        return

    for i, device in enumerate(devices, start=1):
        print(f"\nDevice {i}")
        print(f"Name: {device.get('name', 'Unknown')}")
        print(f"IP: {device.get('ip', 'N/A')}")
        print(f"Status: {device.get('status', 'Unknown')}")

    print(f"\nTotal: {len(devices)}")


def run_network_scan():
    try:
        scanned_devices = scan_network()
        previous_devices = load_previous_scan()

        if previous_devices is None:
            new_devices = []
        else:
            new_devices = detect_new_devices(
                scanned_devices,
                previous_devices
            )

        print("\n--- Scan Results ---")

        for device in scanned_devices:
            print(f"\nIP: {device['ip']}")
            print(f"MAC: {device.get('mac') or 'N/A'}")
            print(f"Vendor: {device.get('vendor', 'Unknown')}")
            print(f"Status: {device['status']}")

        print(f"\nHosts found: {len(scanned_devices)}")

        if previous_devices is None:
            print("First scan saved as baseline.")

        elif new_devices:
            print("\nNew devices/IPs detected:")

            for device in new_devices:
                print(f"- {device['ip']}")

        else:
            print("No new devices/IPs detected.")

        save_scan(scanned_devices)
        save_history(scanned_devices, new_devices)

        print("Scan results saved!")

        if new_devices:
            print(
                f"ALERT: {len(new_devices)} "
                "new device/IP record(s) detected!"
            )

    except Exception as error:
        print(f"Scan failed: {error}")


def main():
    show_welcome()
    devices = load_devices()

    while True:
        print("\n1. Add Device")
        print("2. Show Devices")
        print("3. Scan Network")
        print("4. Show Scan History")
        print("5. Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            add_device(devices)

        elif choice == "2":
            show_devices(devices)

        elif choice == "3":
            run_network_scan()

        elif choice == "4":
            show_history()

        elif choice == "5":
            print("Goodbye!")
            break

        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
