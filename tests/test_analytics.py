from pathlib import Path

from backend.analytics import build_dashboard_metrics
from backend.db import Database


def test_build_dashboard_metrics_aggregates_totals(tmp_path):
    db_path = tmp_path / "metrics.db"
    database = Database(str(db_path))

    ssh_events = [
        {
            "event_time": "2025-11-14T12:00:00Z",
            "ip_address": "203.0.113.7",
            "username": "admin",
            "raw": "ssh log",
        },
        {
            "event_time": "2025-11-14T12:05:00Z",
            "ip_address": "203.0.113.7",
            "username": "root",
            "raw": "ssh log",
        },
    ]
    apache_events = [
        {
            "event_time": "2025-11-14T12:10:00Z",
            "ip_address": "198.51.100.24",
            "request": "GET /admin/login HTTP/1.1",
            "status_code": 404,
            "raw": "apache log",
        }
    ]
    alerts = [
        {
            "indicator": "203.0.113.7",
            "log_source": "ssh",
            "severity": "high",
            "message": "match",
            "event_time": "2025-11-14T12:05:00Z",
            "meta": {},
        }
    ]

    database.replace_log_events("ssh", ssh_events)
    database.replace_log_events("apache", apache_events)
    database.store_alerts(alerts)

    metrics = build_dashboard_metrics(database)

    assert metrics["totals"] == {"ssh_events": 2, "apache_events": 1, "alerts": 1}
    assert metrics["ssh_top_ips"][0]["ip"] == "203.0.113.7"
    assert any(item["status"] == "404" for item in metrics["apache_status_counts"])
    assert metrics["alert_severity_counts"][0]["severity"] == "high"
