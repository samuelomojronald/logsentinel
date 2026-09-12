"""Command-line interface: logsentinel scan <logfile> [options]"""

from __future__ import annotations

import argparse
import sys

from .detector import BruteForceAnalyzer
from .parser import detect_format_and_parse
from .report import to_console, to_html, to_json


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="logsentinel",
        description="Detect brute-force and credential-stuffing patterns in auth logs.",
    )
    p.add_argument("logfile", help="Path to an auth.log / secure log or access log file")
    p.add_argument(
        "--format",
        choices=["auto", "ssh", "web"],
        default="auto",
        help="Log format (default: auto-detect)",
    )
    p.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed attempts from one IP to trigger a brute-force alert (default: 5)",
    )
    p.add_argument(
        "--window",
        type=int,
        default=60,
        help="Sliding time window in seconds (default: 60)",
    )
    p.add_argument(
        "--output",
        choices=["console", "json", "html"],
        default="console",
        help="Report format (default: console)",
    )
    p.add_argument("--out-file", help="Write the report to this file instead of stdout")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        with open(args.logfile, "r", errors="replace") as f:
            lines = f.readlines()
    except OSError as exc:
        print(f"error: could not read {args.logfile}: {exc}", file=sys.stderr)
        return 1

    from .parser import parse_ssh_log, parse_web_log

    if args.format == "ssh":
        events = list(parse_ssh_log(lines))
    elif args.format == "web":
        events = list(parse_web_log(lines))
    else:
        events = list(detect_format_and_parse(lines))

    events.sort(key=lambda e: e.timestamp)

    analyzer = BruteForceAnalyzer(fail_threshold=args.threshold, window_seconds=args.window)
    analyzer.feed_all(events)
    alerts = analyzer.alerts()

    renderer = {"console": to_console, "json": to_json, "html": to_html}[args.output]
    report = renderer(alerts, analyzer.total_events)

    if args.out_file:
        with open(args.out_file, "w") as f:
            f.write(report)
        print(f"Report written to {args.out_file} ({len(alerts)} alerts)")
    else:
        print(report)

    # Non-zero exit when critical/high alerts exist — useful for CI/cron.
    return 2 if any(a.severity in ("critical", "high") for a in alerts) else 0


if __name__ == "__main__":
    sys.exit(main())
