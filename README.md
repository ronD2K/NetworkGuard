
# NetworkGuard

A Python-based home network monitoring project built
to practice networking, cybersecurity, and software
development fundamentals.

## Overview

NetworkGuard is a local network discovery and
monitoring tool.

It uses Nmap to discover active hosts, stores scan
history, and compares scan results to identify
newly detected IP addresses.

A Streamlit dashboard provides a simple interface
for monitoring devices and reviewing scan history.

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

## Technologies

- Python
- Nmap
- Streamlit
- Pytest
- JSON
- XML
- Git and GitHub

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
└── tests/
    ├── test_monitor.py
    ├── test_scanner.py
    └── test_history.py
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/ronnieD2K/NetworkGuard.git
cd NetworkGuard
```

### 2. Install Python dependencies

```bash
python -m pip install -r requirements.txt
```

### 3. Install Nmap

Install Nmap from:

https://nmap.org/download.html

Ensure that the `nmap` command is available.

### 4. Configure the network

Open `scanner.py` and configure `NETWORK`
for a private network you own or are authorized
to scan.

### 5. Launch the dashboard

```bash
python -m streamlit run dashboard.py
```

## Running Tests

```bash
python -m pytest tests -v
```

The project currently includes 12 automated
tests covering scanning, monitoring, and history
functionality.

## Limitations

- Designed for local, authorized networks only.
- Some devices may not respond to network discovery.
- MAC addresses and vendors may be unavailable.
- A newly detected IP does not necessarily
  indicate a security threat.
- A missing IP does not prove a device is offline.
- Monitoring requires manual scans.

## Security and Privacy

NetworkGuard is intended for educational use.

Scan results and device information are stored
locally and excluded from Git using .gitignore.

Do not scan networks without authorization.

## Author

Quang Doan

CSIS Student at Douglas College

Interested in Python, networking, and cybersecurity.
