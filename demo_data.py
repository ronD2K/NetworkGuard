
from datetime import datetime, timedelta, timezone


DEMO_DEVICES = [
    {
        "ip": "192.0.2.1",
        "mac": "02:00:00:00:00:01",
        "vendor": "Demo Router",
        "status": "Online"
    },
    {
        "ip": "192.0.2.10",
        "mac": "02:00:00:00:00:10",
        "vendor": "Demo Laptop",
        "status": "Online"
    },
    {
        "ip": "192.0.2.20",
        "mac": "02:00:00:00:00:20",
        "vendor": "Demo Smartphone",
        "status": "Online"
    },
    {
        "ip": "192.0.2.30",
        "mac": "02:00:00:00:00:30",
        "vendor": "Demo Smart TV",
        "status": "Online"
    },
    {
        "ip": "192.0.2.40",
        "mac": "02:00:00:00:00:40",
        "vendor": "Demo Tablet",
        "status": "Online"
    }
]


def get_demo_data():
    now = datetime.now(timezone.utc)

    first_scan = DEMO_DEVICES[:3]
    second_scan = DEMO_DEVICES[:4]
    third_scan = DEMO_DEVICES[:5]

    history = [
        {
            "timestamp": (
                now - timedelta(hours=2)
            ).isoformat(timespec="seconds"),
            "total_devices": len(first_scan),
            "devices": first_scan,
            "new_devices": []
        },
        {
            "timestamp": (
                now - timedelta(hours=1)
            ).isoformat(timespec="seconds"),
            "total_devices": len(second_scan),
            "devices": second_scan,
            "new_devices": [DEMO_DEVICES[3]]
        },
        {
            "timestamp": now.isoformat(
                timespec="seconds"
            ),
            "total_devices": len(third_scan),
            "devices": third_scan,
            "new_devices": [DEMO_DEVICES[4]]
        }
    ]

    return list(DEMO_DEVICES), history
