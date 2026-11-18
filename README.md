
# NetworkGuard

[![NetworkGuard Tests](https://github.com/ronD2K/NetworkGuard/actions/workflows/tests.yml/badge.svg)](https://github.com/ronD2K/NetworkGuard/actions/workflows/tests.yml)

A Python-based home network monitoring project built to practice networking, cybersecurity, and software development fundamentals.

## Overview

NetworkGuard is a local network discovery and monitoring tool.

It uses Nmap to discover active hosts, stores scan history, and compares scan results to identify newly detected IP addresses.

A Streamlit dashboard provides a simple interface for monitoring devices and reviewing scan history.

## Features

- Local network scanning using Nmap
- Active host discovery
- IP address and available MAC/vendor information
- New device/IP detection
- Scan history stored locally in JSON
- Streamlit web dashboard
- Device monitoring between recent scans
- Security alert history
- CSV export
- Automated unit tests using Pytest
- Continuous Integration with GitHub Actions

## Technologies

- Python
- Nmap
- Streamlit
- Pytest
- JSON
- XML
- Git and GitHub
- GitHub Actions

## Project Structure

```text
NetworkGuard/
├── main.py
├── scanner.py
├── monitor.py
├── history.py
├── dashboard.py
├── requirements.txt
├── .gitignore
├── .github/
│   └── workflows/
│       └── tests.yml
└── tests/
    ├── test_monitor.py
    ├── test_scanner.py
    └── test_history.py
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/ronD2K/NetworkGuard.git
cd NetworkGuard
```

### 2. Install Python dependencies

```bash
python -m pip install -r requirements.txt
```

### 3. Install Nmap

Download and install Nmap:

https://nmap.org/download.html

Ensure that the `nmap` command is available from your terminal.

### 4. Configure the network

Open `scanner.py` and configure the `NETWORK` variable for a private network you own or have permission to scan.

### 5. Launch the dashboard

```bash
python -m streamlit run dashboard.py
```

## Running Tests

Run automated tests with:

```bash
python -m pytest tests -v
```

NetworkGuard includes 12 automated tests covering:

- Network scanning and XML parsing
- Device detection
- Scan history management
- Error handling
- Mock network scans

## Continuous Integration

GitHub Actions automatically runs the test suite when code is pushed to the `main` branch or a pull request targets `main`.

The CI workflow uses Python and Pytest to check that existing functionality continues to work.

## Limitations

- Designed for local, authorized networks only.
- Some devices may not respond to network discovery.
- MAC addresses and vendors may be unavailable.
- Newly detected IP addresses do not necessarily indicate security threats.
- A missing IP does not prove that a device is offline.
- Monitoring currently requires manual scans.

## Security and Privacy

NetworkGuard is intended for educational use.

Scan results and device information are stored locally and excluded from Git using `.gitignore`.

Only scan networks you own or have explicit permission to test.

## Author

**Quang Doan**

CSIS Student at Douglas College

Interested in Python, networking, and cybersecurity.
