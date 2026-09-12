import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from logsentinel.detector import BruteForceAnalyzer
from logsentinel.parser import parse_ssh_log
from scripts.macos_export_ssh_log import convert as macos_convert

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "sample_logs", "auth.log.sample")


def load_events():
    with open(SAMPLE) as f:
        lines = f.readlines()
    events = list(parse_ssh_log(lines))
    events.sort(key=lambda e: e.timestamp)
    return events


def test_parser_extracts_all_lines():
    events = load_events()
    assert len(events) == 16


def test_parser_identifies_success_and_failure():
    events = load_events()
    successes = [e for e in events if e.success]
    failures = [e for e in events if not e.success]
    assert len(successes) == 2
    assert len(failures) == 14


def test_brute_force_alert_triggered():
    events = load_events()
    analyzer = BruteForceAnalyzer(fail_threshold=5, window_seconds=60)
    analyzer.feed_all(events)
    alerts = analyzer.alerts()
    kinds = {a.kind for a in alerts}
    assert "brute_force" in kinds
    bf = [a for a in alerts if a.kind == "brute_force"]
    assert any(a.ip == "203.0.113.7" for a in bf)


def test_success_after_failures_flagged_critical():
    events = load_events()
    analyzer = BruteForceAnalyzer(fail_threshold=5, window_seconds=60)
    analyzer.feed_all(events)
    alerts = analyzer.alerts()
    critical = [a for a in alerts if a.severity == "critical"]
    assert any(a.kind == "success_after_failures" and a.ip == "203.0.113.7" for a in critical)


def test_low_volume_ip_not_flagged():
    events = load_events()
    analyzer = BruteForceAnalyzer(fail_threshold=5, window_seconds=60)
    analyzer.feed_all(events)
    alerts = analyzer.alerts()
    bf_ips = {a.ip for a in alerts if a.kind == "brute_force"}
    assert "198.51.100.9" not in bf_ips  # only 2 failures, below threshold


def test_credential_stuffing_detected_for_many_usernames():
    events = load_events()
    analyzer = BruteForceAnalyzer(fail_threshold=100, window_seconds=60, user_enum_threshold=4)
    analyzer.feed_all(events)
    alerts = analyzer.alerts()
    enum_alerts = [a for a in alerts if a.kind == "credential_stuffing"]
    assert any(a.ip == "45.33.32.156" for a in enum_alerts)


def test_macos_log_conversion_is_parseable():
    raw = [
        "2026-09-12 03:14:01.123456-0700  localhost sshd[501]: "
        "Failed password for invalid user admin from 203.0.113.7 port 51501 ssh2",
        "2026-09-12 03:14:31.654321-0700  localhost sshd[501]: "
        "Accepted password for ubuntu from 203.0.113.7 port 51507 ssh2",
        "2026-09-12 03:14:32.000000-0700  localhost sshd[502]: some unrelated pam message",
    ]
    converted = macos_convert(raw, "MacBook-Air")
    assert len(converted) == 2  # the unrelated line is dropped
    events = list(parse_ssh_log(converted))
    assert len(events) == 2
    assert events[0].ip == "203.0.113.7"
    assert events[0].success is False
    assert events[1].success is True
