
import json
import csv
import io
import html
from pathlib import Path
from datetime import datetime

import streamlit as st
import streamlit.components.v1 as components

from scanner import scan_network, NETWORK
from monitor import (
    load_previous_scan,
    save_scan,
    detect_new_devices
)
from history import save_history


# ==========================================
# 1. CONFIGURATION
# ==========================================

BASE_DIR = Path(__file__).resolve().parent
HISTORY_FILE = BASE_DIR / "scan_history.json"

st.set_page_config(
    page_title="NetworkGuard",
    page_icon="🛡️",
    layout="wide"
)


# ==========================================
# 2. LOAD DATA
# ==========================================

def load_history():
    if not HISTORY_FILE.exists():
        return []

    try:
        with HISTORY_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)

        if isinstance(data, list):
            return [
                record for record in data
                if isinstance(record, dict)
            ]

    except (OSError, json.JSONDecodeError):
        st.warning("Unable to load scan history.")

    return []


def get_latest_devices():
    try:
        return load_previous_scan() or []
    except (OSError, json.JSONDecodeError):
        return []


# ==========================================
# 3. DEVICE MONITORING
# ==========================================

def compare_scans(history):
    if len(history) < 2:
        return [], []

    previous = history[-2].get("devices", [])
    current = history[-1].get("devices", [])

    if not isinstance(previous, list):
        previous = []

    if not isinstance(current, list):
        current = []

    previous_ips = {
        device.get("ip")
        for device in previous
        if isinstance(device, dict) and device.get("ip")
    }

    current_ips = {
        device.get("ip")
        for device in current
        if isinstance(device, dict) and device.get("ip")
    }

    appeared = sorted(current_ips - previous_ips)
    missing = sorted(previous_ips - current_ips)

    return appeared, missing


# ==========================================
# 4. CSV EXPORT
# ==========================================

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


def export_devices(devices):
    columns = ["ip", "mac", "vendor", "status"]

    return make_csv(devices, columns)


def export_history(history):
    rows = []

    for record in history:
        rows.append({
            "timestamp": record.get("timestamp", ""),
            "hosts": record.get("total_devices", 0),
            "new_ips": len(
                record.get("new_devices") or []
            )
        })

    return make_csv(
        rows,
        ["timestamp", "hosts", "new_ips"]
    )


# ==========================================
# 5. ANALYTICS CHART
# ==========================================

def show_analytics_chart(history):
    st.subheader("Network Activity")

    records = history[-30:]

    if not records:
        st.info("No scan history available.")
        return

    values = [
        int(record.get("total_devices") or 0)
        for record in records
    ]

    timestamps = [
        str(record.get("timestamp", "Unknown"))
        for record in records
    ]

    width = 800
    height = 300

    left = 65
    right = 35
    top = 35
    bottom = 65

    plot_width = width - left - right
    plot_height = height - top - bottom

    upper = max(max(values) + 2, 5)
    count = len(values)

    points = []

    for i, value in enumerate(values):
        if count == 1:
            x = left + plot_width / 2
        else:
            x = left + i * plot_width / (count - 1)

        y = top + plot_height * (1 - value / upper)

        points.append((x, y))

    coordinates = " ".join(
        f"{x:.1f},{y:.1f}"
        for x, y in points
    )

    svg = f"""
    <svg viewBox="0 0 {width} {height}"
         xmlns="http://www.w3.org/2000/svg"
         style="width:100%;height:auto">

      <rect width="100%" height="100%"
            rx="12" fill="#111827"/>

      <line x1="{left}" y1="{top}"
            x2="{left}" y2="{height-bottom}"
            stroke="#64748b"/>

      <line x1="{left}" y1="{height-bottom}"
            x2="{width-right}" y2="{height-bottom}"
            stroke="#64748b"/>

      <text x="18" y="{top+5}"
            fill="white" font-size="14">
        {upper}
      </text>

      <text x="25" y="{height-bottom+5}"
            fill="white" font-size="14">
        0
      </text>

      <polyline points="{coordinates}"
                fill="none"
                stroke="#38bdf8"
                stroke-width="3"
                stroke-linecap="round"
                stroke-linejoin="round"/>
    """

    for i, (x, y) in enumerate(points):
        tooltip = html.escape(
            f"{timestamps[i]} | {values[i]} hosts"
        )

        svg += f"""
        <circle cx="{x:.1f}" cy="{y:.1f}"
                r="5" fill="#38bdf8"
                stroke="white" stroke-width="1">
          <title>{tooltip}</title>
        </circle>
        """

    first_time = html.escape(
        timestamps[0][:16].replace("T", " ")
    )

    last_time = html.escape(
        timestamps[-1][:16].replace("T", " ")
    )

    svg += f"""
      <text x="{left}" y="{height-20}"
            fill="#e5e7eb" font-size="13">
        {first_time}
      </text>

      <text x="{width-right}" y="{height-20}"
            text-anchor="end"
            fill="#e5e7eb" font-size="13">
        {last_time}
      </text>
    </svg>
    """

    components.html(
        svg,
        height=325,
        scrolling=False
    )

    st.caption(
        f"Latest {count} scans. "
        "Hover over a point to see the scan time."
    )


# ==========================================
# 6. DEVICE INVENTORY
# ==========================================

def show_device_inventory(devices):
    st.subheader("Device Inventory")

    search = st.text_input(
        "Search Devices",
        placeholder="Enter IP, MAC or Vendor..."
    ).strip().lower()

    col1, col2 = st.columns(2)

    with col1:
        exact_ip = st.checkbox("Exact IP Match")

    with col2:
        status_filter = st.selectbox(
            "Filter Status",
            ["All", "Online", "Offline"]
        )

    filtered = []

    for device in devices:
        ip = str(device.get("ip") or "").lower()

        searchable = " ".join([
            ip,
            str(device.get("mac") or ""),
            str(device.get("vendor") or ""),
            str(device.get("status") or "")
        ]).lower()

        if exact_ip and search:
            matches_search = ip == search
        else:
            matches_search = search in searchable

        matches_status = (
            status_filter == "All"
            or device.get("status", "").lower()
            == status_filter.lower()
        )

        if matches_search and matches_status:
            filtered.append(device)

    st.caption(
        f"Showing {len(filtered)} of {len(devices)} devices"
    )

    if not filtered:
        st.info("No matching devices.")
        return

    headers = st.columns([2, 3, 3, 2])

    for col, title in zip(
        headers,
        ["IP Address", "MAC Address", "Vendor", "Status"]
    ):
        col.write(f"**{title}**")

    st.divider()

    for device in filtered:
        cols = st.columns([2, 3, 3, 2])

        cols[0].text(device.get("ip") or "N/A")
        cols[1].text(device.get("mac") or "N/A")
        cols[2].text(device.get("vendor") or "Unknown")
        cols[3].text(device.get("status") or "Unknown")

    st.divider()

    st.subheader("Device Details")

    options = list(range(len(filtered)))

    selected = st.selectbox(
        "Select a device",
        options,
        format_func=lambda i: (
            f"{filtered[i].get('ip', 'Unknown')} - "
            f"{filtered[i].get('vendor', 'Unknown')}"
        )
    )

    device = filtered[selected]

    st.write(f"**IP Address:** {device.get('ip') or 'N/A'}")
    st.write(f"**MAC Address:** {device.get('mac') or 'N/A'}")
    st.write(f"**Vendor:** {device.get('vendor') or 'Unknown'}")
    st.write(f"**Status:** {device.get('status') or 'Unknown'}")


# ==========================================
# 7. SCAN HISTORY
# ==========================================

def show_scan_history(history):
    st.subheader("Scan History")

    if not history:
        st.info("No scan history available.")
        return

    for record in reversed(history[-20:]):
        timestamp = record.get("timestamp", "Unknown")
        total = record.get("total_devices", 0)
        new_devices = record.get("new_devices") or []

        with st.expander(
            f"{timestamp} | {total} hosts"
        ):
            st.write(f"**Hosts Detected:** {total}")
            st.write(f"**New IPs:** {len(new_devices)}")

            for device in record.get("devices", []):
                if isinstance(device, dict):
                    st.text(device.get("ip") or "N/A")


# ==========================================
# 8. SECURITY ALERT HISTORY
# ==========================================

def show_alert_history(history):
    st.subheader("Security Alert History")

    alerts = []

    for record in history:
        timestamp = record.get("timestamp", "Unknown")

        for device in record.get("new_devices") or []:
            if isinstance(device, dict):
                alerts.append({
                    "time": timestamp,
                    "ip": device.get("ip") or "Unknown",
                    "mac": device.get("mac") or "N/A"
                })

    if not alerts:
        st.info("No new-IP alerts recorded.")
        return

    st.warning(
        f"{len(alerts)} historical alert events"
    )

    for alert in reversed(alerts[-20:]):
        with st.expander(
            f"{alert['ip']} | {alert['time']}"
        ):
            st.write(f"**IP:** {alert['ip']}")
            st.write(f"**MAC:** {alert['mac']}")
            st.write(f"**Time:** {alert['time']}")

    st.caption(
        "New IP detection does not automatically "
        "mean a security threat."
    )


# ==========================================
# 9. DASHBOARD HEADER
# ==========================================

st.title("🛡️ NetworkGuard")
st.write("Home Network Security Monitor")
st.caption("Version 2.2 | Python + Nmap + Streamlit")
st.caption(f"Authorized scan target: {NETWORK}")

st.divider()


# ==========================================
# 10. NETWORK SCANNER
# ==========================================

st.subheader("Network Scanner")

if st.button("🔍 Scan Network", type="primary"):
    with st.spinner("Scanning network..."):
        try:
            devices = scan_network()
            previous = load_previous_scan()

            if previous is None:
                new_devices = []
            else:
                new_devices = detect_new_devices(
                    devices, previous
                )

            # Save history before updating latest scan
            save_history(devices, new_devices)
            save_scan(devices)

        except Exception as error:
            st.error(f"Network scan failed: {error}")

        else:
            st.success("Network scan completed!")

            if previous is None:
                st.info("First scan saved as baseline.")

            elif new_devices:
                st.warning(
                    f"{len(new_devices)} new device/IP "
                    "record(s) detected!"
                )

                for device in new_devices:
                    st.write(f"New IP: {device['ip']}")

            else:
                st.success("No new device/IP records detected.")


# ==========================================
# 11. LOAD LATEST DATA
# ==========================================

devices = get_latest_devices()
history = load_history()

appeared, missing = compare_scans(history)

total_alerts = sum(
    len(record.get("new_devices") or [])
    for record in history
)


# ==========================================
# 12. OVERVIEW
# ==========================================

st.divider()
st.subheader("Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Hosts Detected", len(devices))
col2.metric("Total Scans", len(history))
col3.metric("Historical Alerts", total_alerts)
col4.metric("New IPs (Last Comparison)", len(appeared))


# ==========================================
# 13. MAIN DASHBOARD TABS
# ==========================================

tab1, tab2, tab3, tab4 = st.tabs([
    "Devices",
    "Analytics & History",
    "Security Alerts",
    "Device Monitoring"
])


# TAB 1
with tab1:
    show_device_inventory(devices)

    st.divider()

    st.download_button(
        "⬇️ Export Devices CSV",
        data=export_devices(devices),
        file_name="networkguard_devices.csv",
        mime="text/csv"
    )


# TAB 2
with tab2:
    show_analytics_chart(history)

    st.divider()

    show_scan_history(history)

    st.download_button(
        "⬇️ Export Scan History CSV",
        data=export_history(history),
        file_name="networkguard_history.csv",
        mime="text/csv"
    )


# TAB 3
with tab3:
    show_alert_history(history)


# TAB 4
with tab4:
    st.subheader("Device Monitoring")

    if len(history) < 2:
        st.info(
            "At least two scans are required "
            "for comparison."
        )
    else:
        col1, col2 = st.columns(2)

        col1.metric("Newly Detected IPs", len(appeared))
        col2.metric("Not Detected This Scan", len(missing))

        st.divider()

        st.write("### Newly Detected IP Addresses")

        if appeared:
            for ip in appeared:
                st.write(f"🟢 {ip}")
        else:
            st.info("No newly detected IP addresses.")

        st.write("### IPs Not Detected in Latest Scan")

        if missing:
            for ip in missing:
                st.write(f"🟠 {ip}")
        else:
            st.info("No missing IP addresses.")

        st.caption(
            "Comparison uses IP addresses from the "
            "two latest scans. A missing IP does not "
            "prove the device is offline. DHCP changes "
            "and discovery failures may affect results."
        )


# ==========================================
# 14. FOOTER
# ==========================================

st.divider()

st.caption(
    "NetworkGuard v2.2 | Local Network Monitoring Project"
)
