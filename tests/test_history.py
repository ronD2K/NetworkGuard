
import json
import history


def test_save_scan_history(tmp_path, monkeypatch):
    test_file = tmp_path / "scan_history.json"

    monkeypatch.setattr(
        history,
        "HISTORY_FILE",
        test_file
    )

    devices = [
        {
            "ip": "10.0.0.10",
            "status": "Online"
        }
    ]

    history.save_history(devices, [])

    assert test_file.exists()

    with test_file.open(
        "r",
        encoding="utf-8"
    ) as file:
        data = json.load(file)

    assert len(data) == 1
    assert data[0]["total_devices"] == 1
    assert data[0]["new_devices"] == []


def test_history_appends_records(tmp_path, monkeypatch):
    test_file = tmp_path / "scan_history.json"

    monkeypatch.setattr(
        history,
        "HISTORY_FILE",
        test_file
    )

    history.save_history([], [])
    history.save_history([], [])

    with test_file.open(
        "r",
        encoding="utf-8"
    ) as file:
        data = json.load(file)

    assert len(data) == 2
