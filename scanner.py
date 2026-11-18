
import os
import subprocess
import ipaddress
import xml.etree.ElementTree as ET


# Network configuration is stored locally.
# Example environment variable:
# NETWORKGUARD_SUBNET=192.168.1.0/24

NETWORK = os.getenv(
    "NETWORKGUARD_SUBNET", ""
).strip()


# RFC 1918 private IPv4 address ranges
ALLOWED_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)


def validate_network(network_text):
    """
    Validate a network before scanning.

    Rules:
    - Configuration must not be empty.
    - Only IPv4 is supported.
    - Only RFC 1918 private ranges are allowed.
    - Maximum scan size is a /24 subnet.
    """

    if not network_text or not network_text.strip():
        raise ValueError(
            "No network configured. Set NETWORKGUARD_SUBNET "
            "before using Live Mode."
        )

    try:
        network = ipaddress.ip_network(
            network_text.strip(),
            strict=True
        )

    except ValueError as error:
        raise ValueError(
            "Invalid network configuration. "
            "Use a valid CIDR subnet."
        ) from error

    if network.version != 4:
        raise ValueError(
            "Only private IPv4 networks are supported."
        )

    if not any(
        network.subnet_of(allowed)
        for allowed in ALLOWED_NETWORKS
    ):
        raise ValueError(
            "Only RFC 1918 private IPv4 networks "
            "are supported."
        )

    if network.prefixlen < 24:
        raise ValueError(
            "Network range is too large. "
            "Use a /24 or smaller subnet."
        )

    return network


def parse_nmap_xml(xml_output):
    """
    Parse Nmap XML output and return
    a list of active IPv4 devices.
    """

    root = ET.fromstring(xml_output)

    devices = []
    seen_ips = set()

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
            address_value = address.get("addr")

            if address_type == "ipv4":
                if not address_value:
                    continue

                try:
                    valid_ip = ipaddress.IPv4Address(
                        address_value
                    )

                except ipaddress.AddressValueError:
                    continue

                device["ip"] = str(valid_ip)

            elif address_type == "mac":

                if address_value:
                    device["mac"] = address_value

                device["vendor"] = (
                    address.get("vendor") or "Unknown"
                )

        ip = device["ip"]

        if ip and ip not in seen_ips:
            devices.append(device)
            seen_ips.add(ip)

    return devices


def scan_network():
    """
    Discover active hosts on the
    configured authorized local network.
    """

    network = validate_network(NETWORK)

    command = [
        "nmap",
        "-sn",
        "-oX",
        "-",
        str(network)
    ]

    try:
        result = subprocess.run(
            command,
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
            "Nmap was not found. "
            "Check that Nmap is installed and on PATH."
        ) from error

    except subprocess.CalledProcessError as error:
        details = (
            error.stderr or "Unknown Nmap error"
        ).strip()

        raise RuntimeError(
            f"Nmap scan failed: {details}"
        ) from error

    try:
        devices = parse_nmap_xml(
            result.stdout
        )

    except ET.ParseError as error:
        raise RuntimeError(
            "Nmap returned invalid XML data."
        ) from error

    return devices
