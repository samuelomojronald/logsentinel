"""Render Alert lists as console text, JSON, or a standalone HTML report."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from typing import List

from .detector import Alert

_SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}


def to_console(alerts: List[Alert], total_events: int) -> str:
    lines = [
        f"LogSentinel report — {len(alerts)} alert(s) from {total_events} parsed events",
        "=" * 60,
    ]
    if not alerts:
        lines.append("No suspicious activity detected.")
    for a in alerts:
        icon = _SEVERITY_ICON.get(a.severity, "•")
        lines.append(f"{icon} [{a.severity.upper():8}] {a.kind:22} ip={a.ip}")
        lines.append(f"    {a.detail}")
        lines.append(f"    window: {a.first_seen} -> {a.last_seen}")
        lines.append("")
    return "\n".join(lines)


def to_json(alerts: List[Alert], total_events: int) -> str:
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_events_parsed": total_events,
        "alert_count": len(alerts),
        "alerts": [asdict(a) for a in alerts],
    }
    return json.dumps(payload, indent=2)


def to_html(alerts: List[Alert], total_events: int) -> str:
    rows = "\n".join(
        f"<tr class='{a.severity}'>"
        f"<td>{_SEVERITY_ICON.get(a.severity,'')} {a.severity}</td>"
        f"<td>{a.kind}</td><td>{a.ip}</td><td>{a.detail}</td>"
        f"<td>{a.first_seen}</td><td>{a.last_seen}</td></tr>"
        for a in alerts
    )
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>LogSentinel Report</title>
<style>
body {{ font-family: -apple-system, Arial, sans-serif; margin: 2rem; background:#0b0f14; color:#e6edf3; }}
h1 {{ font-size: 1.4rem; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
th, td {{ border: 1px solid #30363d; padding: 8px 10px; text-align: left; font-size: 0.9rem; }}
th {{ background: #161b22; }}
tr.critical {{ background: #3b0d0d; }}
tr.high {{ background: #3a220a; }}
tr.medium {{ background: #3a3308; }}
tr.low {{ background: #0d2a12; }}
.summary {{ color:#8b949e; }}
</style></head>
<body>
<h1>LogSentinel Security Report</h1>
<p class="summary">Generated {datetime.utcnow().isoformat()}Z &middot; {total_events} events parsed &middot; {len(alerts)} alerts</p>
<table>
<tr><th>Severity</th><th>Type</th><th>IP</th><th>Detail</th><th>First seen</th><th>Last seen</th></tr>
{rows if alerts else '<tr><td colspan="6">No suspicious activity detected.</td></tr>'}
</table>
</body></html>"""
