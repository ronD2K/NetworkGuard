
from types import SimpleNamespace
import subprocess

import pytest
import scanner


SAMPLE_XML = """
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.10" addrtype="ipv4"/>
    <address
      addr="AA:BB:CC:DD:EE:FF"
      addrtype="mac"
      vendor="Test Vendor"
    />
  </host>
  <host>
    <status state="down"/>
    <address addr="10.0.0.20" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


def test_parse_nmap_xml():
    devices = scanner.parse_nmap_xml(SAMPLE_XML)

    assert len(devices) == 1
    assert devices[0]["ip"] == "10.0.0.10"
    assert devices[0]["vendor"] == "Test Vendor"
    assert devices[0]["status"] == "Online"


def test_scan_network_mock(monkeypatch):
    def fake_run(*args, **kwargs):
        return SimpleNamespace(stdout=SAMPLE_XML)

    monkeypatch.setattr(
        scanner.subprocess,
        "run",
        fake_run
    )

    devices = scanner.scan_network()

    assert len(devices) == 1
    assert devices[0]["ip"] == "10.0.0.10"


def test_scan_timeout(monkeypatch):
    def fake_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd="nmap",
            timeout=60
        )

    monkeypatch.setattr(
        scanner.subprocess,
        "run",
        fake_timeout
    )

    with pytest.raises(
        RuntimeError,
        match="timed out"
    ):
        scanner.scan_network()


def test_nmap_not_installed(monkeypatch):
    def fake_missing(*args, **kwargs):
        raise FileNotFoundError("nmap")

    monkeypatch.setattr(
        scanner.subprocess,
        "run",
        fake_missing
    )

    with pytest.raises(
        RuntimeError,
        match="not found"
    ):
        scanner.scan_network()


def test_invalid_xml():
    with pytest.raises(
        scanner.ET.ParseError
    ):
        scanner.parse_nmap_xml("<invalid>")


def test_invalid_network_configuration(monkeypatch):
    monkeypatch.setattr(
        scanner,
        "NETWORK",
        "invalid-subnet"
    )

    with pytest.raises(ValueError):
        scanner.scan_network()
