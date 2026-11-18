
import os
import subprocess
import ipaddress
import xml.etree.ElementTree as ET


# Read the network from the local environment.
# No personal subnet is stored in public source code.
NETWORK = os.getenv("NETWORKGUARD_SUBNET", "").strip()


def validate_network(network_text):
    if not network_text:
        raise ValueError(
            "No network configured. Set NETWORKGUARD_SUBNET "
            "before using Live Mode."
        )

    network = ipaddress.ip_network(
        network_text,
        strict=True
    )

    if network.version != 4 or not network.is_private:
        raise ValueError(
            "Only private IPv4 networks are supported."
        )

    # Prevent accidentally scanning very large ranges.
    if network.prefixlen < 24:
        raise ValueError(
            "Network range is too large. "
            "Use a /24 or smaller subnet."
        )

    return network


def parse_nmap_xml(xml_output):
    root = ET.fromstring(xml_output)
    devices = []

    for host in root.findall("host"):
        status = host.find("status")

        if status is None or status.get("state") != "up":
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
    network = validate_network(NETWORK)

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
        return parse_nmap_xml(result.stdout)

    except ET.ParseError as error:
        raise RuntimeError(
            "Nmap returned invalid XML data."
        ) from error
