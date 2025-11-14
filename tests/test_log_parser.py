from pathlib import Path

from backend import log_parser


def test_parse_ssh_log_extracts_failed_password(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Nov 14 12:34:56 cybersentinel sshd[9132]: Failed password for invalid user admin "
        "from 203.0.113.7 port 4242 ssh2\n",
        encoding="utf-8",
    )

    events = log_parser.parse_ssh_log(log_file)

    assert len(events) == 1
    event = events[0]
    assert event["ip_address"] == "203.0.113.7"
    assert event["username"] == "admin"
    assert event["meta"]["port"] == "4242"


def test_parse_apache_access_log_handles_status_and_request(tmp_path):
    log_file = tmp_path / "access.log"
    log_file.write_text(
        "198.51.100.24 - - [14/Nov/2025:12:00:01 +0000] \"GET /admin/login HTTP/1.1\" 404 512\n",
        encoding="utf-8",
    )

    events = log_parser.parse_apache_access_log(log_file)

    assert len(events) == 1
    event = events[0]
    assert event["ip_address"] == "198.51.100.24"
    assert event["status_code"] == 404
    assert event["request"] == "GET /admin/login HTTP/1.1"
    assert event["meta"]["bytes"] == 512
