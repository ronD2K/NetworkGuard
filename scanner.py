
import subprocess
import ipaddress
import xml.etree.ElementTree as ET


# Scan only your authorized local network
NETWORK = "10.0.0.0/24"


def parse_nmap_xml(xml_output):
    root = ET.fromstring(xml_output)
    devices = []

    for host in root.findall("host"):
        status = host.find("status")

        if status is None:
            continue

        if status.get("state") != "up":
            continue

        device = {
            "ip": None,
            "mac": None,
            "vendor": "Unknown",
            "status": "Online"
        }

        for address in host.findall("address"):
            address_type = address.get("addrtype")

            if address_type == "ipv4":
                device["ip"] = address.get("addr")

            elif address_type == "mac":
                device["mac"] = address.get("addr")
                device["vendor"] = (
                    address.get("vendor") or "Unknown"
                )

        if device["ip"]:
            devices.append(device)

    return devices


def scan_network():
    print("\nScanning network...")

    # Validate the configured network
    network = ipaddress.ip_network(
        NETWORK,
        strict=True
    )

    if not network.is_private:
        raise ValueError(
            "NetworkGuard only permits private network ranges."
        )

    try:
        result = subprocess.run(
            [
                "nmap",
                "-sn",
                "-oX",
                "-",
                str(network)
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=60
        )

    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            "Nmap scan timed out after 60 seconds."
        ) from error

    except FileNotFoundError as error:
        raise RuntimeError(
            "Nmap was not found. Check installation."
        ) from error

    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            f"Nmap failed: {error.stderr}"
        ) from error

    try:
        devices = parse_nmap_xml(result.stdout)

    except ET.ParseError as error:
        raise RuntimeError(
            "Nmap returned invalid XML data."
        ) from error

    return devices
