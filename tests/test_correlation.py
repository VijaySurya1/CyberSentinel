from backend.correlation import correlate_logs_with_iocs


def test_correlate_logs_with_iocs_generates_alerts_for_matches():
    logs = {
        "ssh": [
            {
                "ip_address": "203.0.113.7",
                "event_time": "2025-11-14T12:00:00Z",
                "raw": "ssh event",
            }
        ],
        "apache": [
            {
                "ip_address": "198.51.100.24",
                "event_time": "2025-11-14T12:05:00Z",
                "raw": "apache event",
            }
        ],
    }
    iocs = [
        {"indicator": "203.0.113.7", "type": "ipv4"},
        {"indicator": "198.51.100.24", "type": "ipv4"},
    ]

    alerts = correlate_logs_with_iocs(logs, iocs)

    indicators = {alert["indicator"] for alert in alerts if alert["indicator"] != "N/A"}
    assert indicators == {"203.0.113.7", "198.51.100.24"}
    severities = {alert["severity"] for alert in alerts if alert["indicator"] != "N/A"}
    assert severities == {"high", "medium"}


def test_correlate_logs_with_iocs_returns_info_when_no_matches():
    logs = {"ssh": [], "apache": []}
    iocs = []

    alerts = correlate_logs_with_iocs(logs, iocs)

    assert alerts == [
        {
            "indicator": "N/A",
            "log_source": "system",
            "severity": "info",
            "message": "No IOC matches detected",
            "event_time": None,
            "meta": {},
        }
    ]
