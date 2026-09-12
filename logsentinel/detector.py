"""
Detection logic: turns a stream of LogEvent objects into Alert objects.

Three detectors are implemented, each catching a distinct attack pattern:

1. BruteForceDetector   - N+ failed attempts from one IP within a time window.
2. CredentialStuffing   - one IP failing logins across many distinct usernames
                           (points at automated username enumeration).
3. SuccessAfterFailures - a successful login immediately following a burst of
                           failures from the same IP (a brute-force that
                           *worked* - the highest-priority alert type).
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Deque, Dict, List, Set

from .parser import LogEvent


@dataclass
class Alert:
    kind: str
    ip: str
    severity: str  # "low" | "medium" | "high" | "critical"
    detail: str
    count: int
    first_seen: str
    last_seen: str


@dataclass
class _IpWindow:
    failures: Deque[LogEvent] = field(default_factory=deque)
    users_tried: Set[str] = field(default_factory=set)


class BruteForceAnalyzer:
    """
    Stateful analyzer. Feed events in chronological order via `feed()`,
    then call `alerts()` for the findings.
    """

    def __init__(
        self,
        fail_threshold: int = 5,
        window_seconds: int = 60,
        user_enum_threshold: int = 4,
    ):
        self.fail_threshold = fail_threshold
        self.window = timedelta(seconds=window_seconds)
        self.user_enum_threshold = user_enum_threshold

        self._windows: Dict[str, _IpWindow] = defaultdict(_IpWindow)
        self._alerts: List[Alert] = []
        self._alerted_bruteforce: Set[str] = set()
        self._alerted_enum: Set[str] = set()
        self.total_events = 0

    def feed(self, event: LogEvent) -> None:
        self.total_events += 1
        w = self._windows[event.ip]

        if not event.success:
            w.failures.append(event)
            if event.user:
                w.users_tried.add(event.user)

            # drop failures outside the sliding window
            cutoff = event.timestamp - self.window
            while w.failures and w.failures[0].timestamp < cutoff:
                w.failures.popleft()

            if len(w.failures) >= self.fail_threshold and event.ip not in self._alerted_bruteforce:
                self._alerted_bruteforce.add(event.ip)
                self._alerts.append(
                    Alert(
                        kind="brute_force",
                        ip=event.ip,
                        severity="high",
                        detail=(
                            f"{len(w.failures)} failed login attempts within "
                            f"{int(self.window.total_seconds())}s"
                        ),
                        count=len(w.failures),
                        first_seen=w.failures[0].timestamp.isoformat(),
                        last_seen=event.timestamp.isoformat(),
                    )
                )

            if (
                len(w.users_tried) >= self.user_enum_threshold
                and event.ip not in self._alerted_enum
            ):
                self._alerted_enum.add(event.ip)
                self._alerts.append(
                    Alert(
                        kind="credential_stuffing",
                        ip=event.ip,
                        severity="medium",
                        detail=(
                            f"failed logins across {len(w.users_tried)} distinct "
                            f"usernames ({', '.join(sorted(w.users_tried))})"
                        ),
                        count=len(w.users_tried),
                        first_seen=w.failures[0].timestamp.isoformat() if w.failures else event.timestamp.isoformat(),
                        last_seen=event.timestamp.isoformat(),
                    )
                )
        else:
            # success: check whether it was preceded by a burst of failures
            if len(w.failures) >= max(3, self.fail_threshold // 2):
                self._alerts.append(
                    Alert(
                        kind="success_after_failures",
                        ip=event.ip,
                        severity="critical",
                        detail=(
                            f"login SUCCEEDED for user "
                            f"'{event.user or 'unknown'}' after {len(w.failures)} "
                            f"prior failures - possible compromised credential"
                        ),
                        count=len(w.failures) + 1,
                        first_seen=w.failures[0].timestamp.isoformat(),
                        last_seen=event.timestamp.isoformat(),
                    )
                )
            # a success clears the failure streak for that IP
            w.failures.clear()

    def feed_all(self, events) -> None:
        for e in events:
            self.feed(e)

    def alerts(self) -> List[Alert]:
        # highest severity first, then most recent
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(self._alerts, key=lambda a: (order.get(a.severity, 9), a.last_seen))
