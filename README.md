# LogSentinel

Lightweight, dependency-free brute-force and credential-stuffing detector for
SSH and web authentication logs. Feed it a log file, get back a prioritized
list of suspicious IPs with the evidence behind each alert.

## Why

Most brute-force attempts leave an obvious trail in `auth.log` or web access
logs, but that trail is easy to miss when you're scrolling raw text. LogSentinel
turns that trail into structured, severity-ranked alerts you can read in
seconds — or wire into a cron job / CI check that fails the build when
something looks wrong.

## Detection logic

| Alert type | Trigger |
|---|---|
| `brute_force` | N+ failed logins from one IP inside a sliding time window (default: 5 in 60s) |
| `credential_stuffing` | One IP failing across many distinct usernames — points at automated enumeration |
| `success_after_failures` | A successful login immediately following a burst of failures from the same IP — the highest-priority signal, since it suggests a brute force that *worked* |

## Supported log formats

- **SSH auth.log / secure log** (`sshd[...]: Failed password for ... from <ip>`)
- **Web access logs** (combined log format), scoped to auth-related paths (`/login`, `/signin`, `/auth`)

Format is auto-detected, or can be forced with `--format ssh|web`.

## Install

```bash
git clone https://github.com/<your-username>/logsentinel.git
cd logsentinel
pip install -r requirements.txt
```

No third-party runtime dependencies — the detector itself is pure Python 3.8+.

## Usage

```bash
python -m logsentinel.cli sample_logs/auth.log.sample
```

```
LogSentinel report — 5 alert(s) from 16 parsed events
============================================================
🔴 [CRITICAL] success_after_failures ip=203.0.113.7
    login SUCCEEDED for user 'ubuntu' after 6 prior failures - possible compromised credential
    window: 2026-09-12T03:14:01 -> 2026-09-12T03:14:31

🟠 [HIGH    ] brute_force            ip=203.0.113.7
    5 failed login attempts within 60s
    window: 2026-09-12T03:14:01 -> 2026-09-12T03:14:21
...
```

### Options

```
--format {auto,ssh,web}   log format (default: auto)
--threshold N             failed attempts to trigger a brute-force alert (default: 5)
--window SECONDS          sliding time window in seconds (default: 60)
--output {console,json,html}
--out-file PATH           write report to a file instead of stdout
```

### JSON output (for piping into other tools / SIEMs)

```bash
python -m logsentinel.cli /var/log/auth.log --output json --out-file report.json
```

### HTML report

```bash
python -m logsentinel.cli /var/log/auth.log --output html --out-file report.html
```

### Exit codes

Returns `2` if any `high` or `critical` alert was raised, `0` otherwise —
safe to use as a cron/CI gate:

```bash
python -m logsentinel.cli /var/log/auth.log || alert-on-call.sh
```

## Testing

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

## Project structure

```
logsentinel/
├── logsentinel/
│   ├── parser.py     # log line -> LogEvent
│   ├── detector.py   # LogEvent stream -> Alert list
│   ├── report.py     # Alert list -> console/JSON/HTML
│   └── cli.py         # argparse entrypoint
├── tests/
├── sample_logs/       # synthetic demo data (no real IPs/PII)
└── .github/workflows/ci.yml
```

## Limitations / roadmap

- No persistent state between runs yet — each invocation analyzes a single
  file top to bottom. A `--state-file` option for continuous/cron use is a
  natural next step.
- No IP reputation / geolocation lookups by design (keeps it dependency-free
  and offline-safe); could be added as an optional enrichment step.
- Web log parser only inspects auth-related paths; extending it to arbitrary
  rate-limiting policies would be a reasonable v2 feature.

## License

MIT — see [LICENSE](LICENSE).
