#!/usr/bin/env python3
"""
macOS has no /var/log/auth.log — SSH auth events live in the unified logging
system instead. This script pulls sshd entries out of `log show` and rewrites
them into classic syslog format so logsentinel's existing SSH parser can read
them unchanged.

Usage:
    python3 scripts/macos_export_ssh_log.py --last 1d > /tmp/mac_auth.log
    python3 -m logsentinel.cli /tmp/mac_auth.log

Requires: macOS, and permission to read the unified log (you may be prompted
for your password / need sudo the first time: `sudo python3 scripts/...`).
"""

from __future__ import annotations

import argparse
import re
import socket
import subprocess
import sys
from datetime import datetime

# `log show --style syslog` timestamp: 2026-09-12 03:14:01.123456-0700
_TS_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.\d+[-+]\d{4}\s+")

# Only lines whose message body matches these are relevant to auth analysis.
_RELEVANT_RE = re.compile(
    r"(Failed password|Accepted password|Failed publickey|Accepted publickey)"
)

# Column layout of `log show --style syslog` varies across macOS versions, so
# rather than parsing fixed columns we just locate "sshd[<pid>]:" (or bare
# "sshd:") wherever it appears in the line and treat everything from there on
# as the sshd message body.
_SSHD_ANCHOR_RE = re.compile(r"sshd(?:\[(?P<pid>\d+)\])?:\s*(?P<body>.*)$")


def fetch_log_lines(last: str) -> list[str]:
    cmd = [
        "log",
        "show",
        "--predicate",
        'process == "sshd"',
        "--style",
        "syslog",
        "--last",
        last,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except FileNotFoundError:
        print("error: `log` command not found — this script only runs on macOS.", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        print(f"error running `log show`: {exc.stderr}", file=sys.stderr)
        sys.exit(1)
    return proc.stdout.splitlines()


def convert(lines: list[str], hostname: str, pid_fallback: int = 0) -> list[str]:
    out = []
    for line in lines:
        if not _RELEVANT_RE.search(line):
            continue
        ts_m = _TS_RE.match(line)
        anchor_m = _SSHD_ANCHOR_RE.search(line)
        if not ts_m or not anchor_m:
            continue

        ts = datetime.strptime(ts_m.group("ts"), "%Y-%m-%d %H:%M:%S")
        classic_ts = f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')}"

        pid = anchor_m.group("pid") or str(pid_fallback)
        body = anchor_m.group("body").strip()
        out.append(f"{classic_ts} {hostname} sshd[{pid}]: {body}")
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--last",
        default="1d",
        help="How far back to pull logs, e.g. 1d, 4h, 30m (default: 1d)",
    )
    args = p.parse_args()

    hostname = socket.gethostname().split(".")[0]
    raw = fetch_log_lines(args.last)
    converted = convert(raw, hostname)

    if not converted:
        print(
            "note: no sshd auth events found in that window "
            "(is Remote Login / SSH enabled, and have there been any login attempts?)",
            file=sys.stderr,
        )

    for line in converted:
        print(line)

    return 0


if __name__ == "__main__":
    sys.exit(main())
