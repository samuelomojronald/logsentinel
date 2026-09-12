"""
Parsers for common authentication log formats.

Supports:
  - Linux SSH auth.log / secure log (sshd) lines
  - Generic HTTP access-log style lines with 401/403 status codes

Each parser yields LogEvent objects, which are format-agnostic so the
detector never needs to know where an event came from.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator, Optional

# --- Data model ---------------------------------------------------------


@dataclass(frozen=True)
class LogEvent:
    timestamp: datetime
    ip: str
    success: bool
    user: Optional[str] = None
    source_line: str = ""


# --- SSH auth.log ---------------------------------------------------------

# Example lines this handles:
#   Sep 12 03:14:07 host sshd[1234]: Failed password for root from 203.0.113.7 port 51514 ssh2
#   Sep 12 03:14:09 host sshd[1234]: Failed password for invalid user admin from 198.51.100.9 port 4422 ssh2
#   Sep 12 03:15:01 host sshd[1234]: Accepted password for deploy from 10.0.0.5 port 22 ssh2
_SSH_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<result>Failed password|Accepted password|Failed publickey|Accepted publickey)"
    r"\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[0-9a-fA-F:.]+)\s+port\s+(?P<port>\d+)"
)

# Syslog timestamps have no year; assume current year unless caller overrides.
_DEFAULT_YEAR = datetime.now().year


def parse_ssh_log(lines: Iterable[str], year: int = _DEFAULT_YEAR) -> Iterator[LogEvent]:
    for line in lines:
        m = _SSH_RE.search(line)
        if not m:
            continue
        try:
            ts = datetime.strptime(f"{year} {m.group('ts')}", "%Y %b %d %H:%M:%S")
        except ValueError:
            continue
        success = m.group("result").startswith("Accepted")
        yield LogEvent(
            timestamp=ts,
            ip=m.group("ip"),
            success=success,
            user=m.group("user"),
            source_line=line.rstrip("\n"),
        )


# --- Generic web access log (combined log format) --------------------------

# Example:
#   203.0.113.7 - - [12/Sep/2026:03:14:07 +0000] "POST /login HTTP/1.1" 401 512
_WEB_RE = re.compile(
    r'^(?P<ip>[0-9a-fA-F:.]+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d{3})'
)


def parse_web_log(lines: Iterable[str]) -> Iterator[LogEvent]:
    for line in lines:
        m = _WEB_RE.search(line)
        if not m:
            continue
        try:
            ts = datetime.strptime(m.group("ts").split()[0], "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            continue
        status = int(m.group("status"))
        # 401/403 on auth-ish paths are treated as failed login attempts;
        # 2xx on the same paths are treated as success.
        is_auth_path = any(p in m.group("path").lower() for p in ("login", "signin", "auth"))
        if not is_auth_path:
            continue
        yield LogEvent(
            timestamp=ts,
            ip=m.group("ip"),
            success=200 <= status < 300,
            user=None,
            source_line=line.rstrip("\n"),
        )


def detect_format_and_parse(lines: Iterable[str]) -> Iterator[LogEvent]:
    """Buffer lines, sniff the format from the first few non-empty lines,
    then dispatch to the right parser."""
    lines = list(lines)
    sample = [l for l in lines[:20] if l.strip()]
    if any(_SSH_RE.search(l) for l in sample):
        yield from parse_ssh_log(lines)
    else:
        yield from parse_web_log(lines)
