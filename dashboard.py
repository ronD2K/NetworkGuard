
import csv
import io
import json
from pathlib import Path
from xml.sax.saxutils import escape

import streamlit as st

from scanner import NETWORK, scan_network
from monitor import (
    load_previous_scan,
    save_scan,
    detect_new_devices,
)
from history import save_history
from demo_data import get_demo_data


BASE_DIR = Path(__file__).resolve().parent
HISTORY_FILE = BASE_DIR / "scan_history.json"

st.set_page_config(
    page_title="NetworkGuard",
    page_icon="🛡️",
    layout="wide",
)


# ------------------------------------------
# DATA HELPERS
# ------------------------------------------

def load_history():
    if not HISTORY_FILE.exists():
        return []

    try:
        with HISTORY_FILE.open(
            "r", encoding="utf-8"
        ) as file:
            data = json.load(file)

        if isinstance(data, list):
            return data

        st.warning("Invalid scan history format.")
        return []

    except (OSError, json.JSONDecodeError):
        st.warning("Unable to load scan history.")
        return []


def get_live_devices():
    data = load_previous_scan()

    if isinstance(data, list):
        return data

    return []


def compare_scans(history):
    if len(history) < 2:
        return [], []

    previous = history[-2].get("devices") or []
    current = history[-1].get("devices") or []

    previous_ips = {
        item.get("ip")
        for item in previous
        if isinstance(item, dict) and item.get("ip")
    }

    current_ips = {
        item.get("ip")
        for item in current
        if isinstance(item, dict) and item.get("ip")
    }

    appeared = sorted(current_ips - previous_ips)
    missing = sorted(previous_ips - current_ips)

    return appeared, missing


def display_mac(mac, show_mac):
    if not mac:
        return "N/A"

    if show_mac:
        return str(mac)

    return "**:**:**:**:**:**"


def make_csv(rows, columns):
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(columns)

    for row in rows:
        writer.writerow([
            row.get(column, "")
            for column in columns
        ])

    return output.getvalue().encode("utf-8-sig")


def export_devices(devices, show_mac):
    rows = []

    for device in devices:
        rows.append({
            "ip": device.get("ip") or "",
            "mac": display_mac(
                device.get("mac"), show_mac
            ),
            "vendor": device.get("vendor") or "",
            "status": device.get("status") or "",
        })

    return make_csv(
        rows,
        ["ip", "mac", "vendor", "status"]
    )


def export_history(history):
    rows = []

    for record in history:
        rows.append({
            "timestamp": record.get(
                "timestamp", ""
            ),
            "hosts": record.get(
                "total_devices", 0
            ),
            "new_ips": len(
                record.get("new_devices") or []
            ),
        })

    return make_csv(
        rows,
        ["timestamp", "hosts", "new_ips"]
    )


# ------------------------------------------
# SVG ANALYTICS - NO PANDAS
# ------------------------------------------

def create_analytics_svg(history):
    records = history[-30:]

    values = [
        int(record.get("total_devices") or 0)
        for record in records
    ]

    timestamps = [
        str(record.get("timestamp") or "Unknown")
        for record in records
    ]

    width = 900
    height = 320

    left = 65
    right = 35
    top = 35
    bottom = 65

    plot_width = width - left - right
    plot_height = height - top - bottom

    upper = max(max(values) + 2, 5)

    points = []

    for i, value in enumerate(values):
        if len(values) == 1:
            x = left + plot_width / 2
        else:
            x = left + (
                i * plot_width / (len(values) - 1)
            )

        y = top + plot_height * (
            1 - value / upper
        )

        points.append((x, y))

    coords = " ".join(
        f"{x:.1f},{y:.1f}"
        for x, y in points
    )

    svg = f"""
    <svg xmlns="http://www.w3.org/2000/svg"
         width="{width}"
         height="{height}"
         viewBox="0 0 {width} {height}">

      <rect width="{width}" height="{height}"
            rx="14" fill="#111827"/>

      <text x="35" y="23"
            font-size="15" fill="#e2e8f0">
        Detected hosts over time
      </text>

      <line x1="{left}" y1="{top}"
            x2="{left}" y2="{height-bottom}"
            stroke="#64748b"/>

      <line x1="{left}" y1="{height-bottom}"
            x2="{width-right}"
            y2="{height-bottom}"
            stroke="#64748b"/>

      <text x="20" y="{top+7}"
            fill="#e2e8f0"
            font-size="14">
        {upper}
      </text>

      <text x="25" y="{height-bottom+5}"
            fill="#e2e8f0"
            font-size="14">
        0
      </text>

      <polyline points="{coords}"
                fill="none"
                stroke="#38bdf8"
                stroke-width="3"
                stroke-linecap="round"
                stroke-linejoin="round"/>
    """

    for i, (x, y) in enumerate(points):
        tooltip = escape(
            f"{timestamps[i]} | {values[i]} hosts"
        )

        svg += f"""
        <circle cx="{x:.1f}" cy="{y:.1f}"
                r="5" fill="#38bdf8"
                stroke="#ffffff" stroke-width="1">
            <title>{tooltip}</title>
        </circle>
        """

    first_time = escape(
        timestamps[0][:16].replace("T", " ")
    )

    last_time = escape(
        timestamps[-1][:16].replace("T", " ")
    )

    svg += f"""
      <text x="{left}" y="{height-20}"
            font-size="13"
            fill="#cbd5e1">
        {first_time}
      </text>

      <text x="{width-right}" y="{height-20}"
            text-anchor="end"
            font-size="13"
            fill="#cbd5e1">
        {last_time}
      </text>
    </svg>
    """

    return svg


def show_analytics_chart(history):
    st.subheader("Network Activity")

    if not history:
        st.info("No scan history available.")
        return

    svg = create_analytics_svg(history)

    # Native Streamlit support for SVG.
    # No Pandas or deprecated HTML component.
    
    assert svg.strip().startswith("<svg"), "Invalid SVG start"

    st.image(
        svg.strip(),
        width="stretch"
    )



    st.caption(
        "Network discovery history. "
        "Values show the number of detected hosts."
    )


# ------------------------------------------
# DEVICE INVENTORY
# ------------------------------------------

def show_devices(devices, show_mac):
    st.subheader("Device Inventory")

    search = st.text_input(
        "Search Devices",
        placeholder="Search IP, MAC, vendor or status..."
    ).strip().lower()

    col1, col2 = st.columns(2)

    with col1:
        exact_ip = st.checkbox("Exact IP Match")

    with col2:
        status_filter = st.selectbox(
            "Status",
            ["All", "Online", "Offline"]
        )

    filtered = []

    for device in devices:
        ip = str(device.get("ip") or "")

        # Search only visible information.
        searchable = " ".join([
            ip,
            display_mac(
                device.get("mac"), show_mac
            ),
            str(device.get("vendor") or ""),
            str(device.get("status") or ""),
        ]).lower()

        if exact_ip and search:
            matches = ip.lower() == search
        else:
            matches = search in searchable

        status_matches = (
            status_filter == "All"
            or str(
                device.get("status") or ""
            ).lower() == status_filter.lower()
        )

        if matches and status_matches:
            filtered.append(device)

    st.caption(
        f"Showing {len(filtered)} of "
        f"{len(devices)} devices"
    )

    if not filtered:
        st.info("No matching devices.")
        return

    cols = st.columns([2, 3, 3, 2])

    for col, title in zip(
        cols,
        ["IP Address", "MAC Address", "Vendor", "Status"]
    ):
        col.write(f"**{title}**")

    st.divider()

    for device in filtered:
        cols = st.columns([2, 3, 3, 2])

        cols[0].text(
            str(device.get("ip") or "N/A")
        )

        cols[1].text(
            display_mac(
                device.get("mac"), show_mac
            )
        )

        cols[2].text(
            str(device.get("vendor") or "Unknown")
        )

        cols[3].text(
            str(device.get("status") or "Unknown")
        )

    st.divider()
    st.subheader("Device Details")

    selected = st.selectbox(
        "Select Device",
        range(len(filtered)),
        format_func=lambda i: (
            f"{filtered[i].get('ip', 'Unknown')} "
            f"- {filtered[i].get('vendor', 'Unknown')}"
        )
    )

    device = filtered[selected]

    st.write(
        f"**IP:** {device.get('ip') or 'N/A'}"
    )

    st.write(
        "**MAC:** "
        + display_mac(
            device.get("mac"), show_mac
        )
    )

    st.write(
        f"**Vendor:** "
        f"{device.get('vendor') or 'Unknown'}"
    )

    st.write(
        f"**Status:** "
        f"{device.get('status') or 'Unknown'}"
    )


# ------------------------------------------
# HISTORY AND SECURITY ALERTS
# ------------------------------------------

def show_scan_history(history, show_mac):
    st.subheader("Scan History")

    if not history:
        st.info("No scan history.")
        return

    for record in reversed(history[-20:]):
        timestamp = record.get(
            "timestamp", "Unknown"
        )

        total = record.get(
            "total_devices", 0
        )

        with st.expander(
            f"{timestamp} | {total} hosts"
        ):
            st.write(
                f"**Hosts:** {total}"
            )

            for device in record.get(
                "devices"
            ) or []:
                st.write(
                    f"{device.get('ip') or 'N/A'} | "
                    f"MAC: {display_mac(device.get('mac'), show_mac)}"
                )


def show_security_alerts(history, show_mac):
    st.subheader("Security Alert History")

    alerts = []

    for record in history:
        for device in (
            record.get("new_devices") or []
        ):
            alerts.append({
                "timestamp": record.get(
                    "timestamp", "Unknown"
                ),
                "ip": device.get(
                    "ip", "Unknown"
                ),
                "mac": device.get("mac"),
            })

    if not alerts:
        st.info("No new-IP alerts recorded.")
        return

    st.warning(
        f"{len(alerts)} historical alert events"
    )

    for alert in reversed(alerts[-20:]):
        with st.expander(
            f"{alert['ip']} | "
            f"{alert['timestamp']}"
        ):
            st.write(
                f"**IP:** {alert['ip']}"
            )

            st.write(
                "**MAC:** "
                + display_mac(
                    alert["mac"], show_mac
                )
            )

            st.write(
                f"**Detected:** {alert['timestamp']}"
            )

    st.caption(
        "An unfamiliar IP does not necessarily "
        "indicate a security threat."
    )


# ------------------------------------------
# APPLICATION
# ------------------------------------------

st.title("🛡️ NetworkGuard")
st.write("Home Network Security Monitor")
st.caption(
    "Version 2.7 | Python + Nmap + Streamlit"
)

st.sidebar.header("Settings")

mode = st.sidebar.radio(
    "Operating Mode",
    ["Demo Mode", "Live Mode"],
    index=0,
)

st.sidebar.divider()

show_mac = st.sidebar.toggle(
    "Show MAC Addresses",
    value=False,
    help="MAC addresses are hidden by default."
)

if show_mac:
    st.sidebar.warning(
        "MAC addresses are visible in the dashboard."
    )
else:
    st.sidebar.success(
        "MAC addresses are hidden."
    )

st.sidebar.caption(
    "This setting affects dashboard display "
    "and device CSV exports, not local JSON files."
)

st.sidebar.divider()


# ------------------------------------------
# DEMO / LIVE DATA
# ------------------------------------------

if mode == "Demo Mode":
    st.sidebar.success("Demo Mode Active")

    st.info(
        "DEMO MODE — All network data is simulated. "
        "No real network scan is performed."
    )

    devices, history = get_demo_data()

else:
    st.sidebar.warning("Live Mode Active")

    if NETWORK:
        st.sidebar.caption(
            f"Configured network: {NETWORK}"
        )
    else:
        st.sidebar.error(
            "NETWORKGUARD_SUBNET is not configured."
        )

    st.subheader("Network Scanner")

    authorized = st.checkbox(
        "I own or have permission to scan "
        "the configured network."
    )

    if st.button(
        "🔍 Scan Network",
        type="primary",
        disabled=not authorized or not NETWORK
    ):
        with st.spinner("Scanning network..."):
            try:
                scanned = scan_network()

                previous = load_previous_scan()

                if previous is None:
                    new_devices = []
                else:
                    new_devices = detect_new_devices(
                        scanned, previous
                    )

                save_history(
                    scanned, new_devices
                )

                save_scan(scanned)

            except (
                ValueError,
                RuntimeError,
                OSError
            ) as error:
                st.error(
                    f"Network scan failed: {error}"
                )

            else:
                st.success(
                    "Network scan completed!"
                )

                if previous is None:
                    st.info(
                        "First scan saved as baseline."
                    )

                elif new_devices:
                    st.warning(
                        f"{len(new_devices)} "
                        "new device/IP record(s) detected."
                    )

                    for device in new_devices:
                        st.write(
                            f"New IP: {device.get('ip')}"
                        )

                else:
                    st.success(
                        "No new device/IP records detected."
                    )

    devices = get_live_devices()
    history = load_history()

    st.caption(
        "Live Mode uses local scan data. "
        "Do not publish real device information."
    )


# ------------------------------------------
# METRICS
# ------------------------------------------

appeared, missing = compare_scans(history)

total_alerts = sum(
    len(record.get("new_devices") or [])
    for record in history
)

st.divider()
st.subheader("Overview")

a, b, c, d = st.columns(4)

a.metric(
    "Hosts Detected",
    len(devices)
)

b.metric(
    "Total Scans",
    len(history)
)

c.metric(
    "Historical Alerts",
    total_alerts
)

d.metric(
    "New IPs (Last Comparison)",
    len(appeared)
)


# ------------------------------------------
# TABS
# ------------------------------------------

tab1, tab2, tab3, tab4 = st.tabs([
    "Devices",
    "Analytics & History",
    "Security Alerts",
    "Device Monitoring",
])


with tab1:
    show_devices(devices, show_mac)

    st.divider()

    st.download_button(
        "⬇️ Export Devices CSV",
        data=export_devices(
            devices, show_mac
        ),
        file_name=(
            "networkguard_demo_devices.csv"
            if mode == "Demo Mode"
            else "networkguard_devices.csv"
        ),
        mime="text/csv",
    )


with tab2:
    show_analytics_chart(history)

    st.divider()

    show_scan_history(
        history, show_mac
    )

    st.download_button(
        "⬇️ Export Scan History CSV",
        data=export_history(history),
        file_name=(
            "networkguard_demo_history.csv"
            if mode == "Demo Mode"
            else "networkguard_history.csv"
        ),
        mime="text/csv",
    )


with tab3:
    show_security_alerts(
        history, show_mac
    )


with tab4:
    st.subheader("Device Monitoring")

    if len(history) < 2:
        st.info(
            "At least two scans are needed "
            "for comparison."
        )

    else:
        c1, c2 = st.columns(2)

        c1.metric(
            "Newly Detected IPs",
            len(appeared)
        )

        c2.metric(
            "Not Detected This Scan",
            len(missing)
        )

        st.divider()

        st.subheader(
            "Newly Detected IP Addresses"
        )

        if appeared:
            for ip in appeared:
                st.write(f"🟢 {ip}")
        else:
            st.info("No newly detected IPs.")

        st.subheader(
            "IPs Not Detected in Latest Scan"
        )

        if missing:
            for ip in missing:
                st.write(f"🟠 {ip}")
        else:
            st.info("No missing IP addresses.")

        st.caption(
            "IP changes, DHCP leases, and "
            "discovery failures can affect results."
        )


# ------------------------------------------
# FOOTER
# ------------------------------------------

st.divider()

st.caption(
    f"NetworkGuard v2.7 | {mode} | "
    "Local Network Monitoring Project"
)
