# GlobalBan

GlobalBan is a local-first defensive monitor for SSH authentication logs and
Windows Security events from XML exports or explicitly requested live polling.
It normalizes a small, explicit set of events, correlates activity over time,
and produces explainable review alerts.
It does not claim to identify a person or intent from an IP address, username,
or process name.

## Requirements and start

- Python 3.10 or newer.
- Runtime uses only the Python standard library. The optional project build
  metadata uses setuptools.
- On Windows, run `python -m pip install -e .`, then `globalban` to open the
  local Tkinter dashboard. Alternatively run `python -m globalban.main` with
  `src` on `PYTHONPATH`.
- Select an SSH auth log or a Windows Event Viewer XML export in the dashboard.
  CLI batch mode is also available:

  ```powershell
  globalban --ssh-log C:\path\to\auth.log
  globalban --windows-xml C:\path\to\Security.xml
  ```

  Live SSH file following is opt-in and starts at the end of the selected file:

  ```powershell
  globalban --follow-ssh-log C:\path\to\auth.log
  ```

  Live Windows Event Log polling is available only when explicitly requested:

  ```powershell
  globalban --windows-live --windows-channel Security
  ```

  Repeat `--windows-channel` for additional channels. Polling requires the
  operator's account to have access to those channels. GlobalBan does not
  enable Windows audit policy or change firewall settings.

## Detection and data handling

- Supported SSH records are OpenSSH failed/accepted login messages and PAM
  `more authentication failures` summaries. Syslog timestamps are interpreted
  in the machine's local timezone; timestamp-less input is assigned its read
  time.
- Windows event normalization supports authentication events 4624 (success),
  4625/4771/4776 (failure), and selected activity events 1102, 1116, 1117,
  4104, 4688, 4698, 4702, 4719, 4720, 4728, 4732, 4756, and 7045. The parser
  retains only an explicit set of host, provider, user, address, process-name,
  and service-name fields; raw XML and unapproved fields are discarded.
- The explainable `AUTH-FAILURE-BURST` rule correlates failures by source IP
  within a configurable time window and requires at least two distinct event
  records in addition to the count threshold. A single aggregated PAM line
  cannot trigger an alert. Its confidence is a heuristic, not a measured
  probability, and the alert explicitly requires human review.
- The SSH baseline stores daily failed-event counts grouped by source IP,
  never username or process. The Windows baseline stores counts keyed by
  hashed host/provider plus event ID; it does not persist names, usernames, or
  raw event text. Both are local explanatory context, not standalone block
  decisions, and either path can be set to `null` to disable persistence.
  Avoid repeatedly importing the same file into a persistent baseline because
  replay detection is not implemented.
- The checked-in examples and evaluation records are fabricated. No precision,
  recall, F1, or accuracy claim is made.
- `detection/sequence.py` can identify a failure-then-success sequence for
  human review and also correlates selected Windows event sequences by host.
  Windows signals require multiple distinct event IDs, include rule reasons
  and static indicator tags, and are review hypotheses rather than confirmed
  compromise findings. Scores/confidence are heuristics, not calibrated
  probabilities or measured accuracy.
- `detection/process_monitor.py` extracts process-creation metadata from event
  4688 and can build bounded process ancestry from observed parent/child PIDs.
  Process names are context only and are never commands or evidence of intent.
- `ingestion/tailer.py` can follow an SSH file after it is explicitly selected,
  reopening it after replacement or truncation. Live following is not started
  by default.
- `ingestion/windows_source.py` polls explicitly configured channels with a
  bounded lookback and record count. The query uses fixed PowerShell syntax,
  deduplicates within the process, and reports query errors; it does not change
  Windows audit settings. Live collection is not started by default.
- `threat_intel.py` supports a read-only local JSON feed. An optional remote
  HTTPS lookup is disabled by default and requires both an enabled client and
  `approved=True` at each call. It sends the exact IP indicator to the
  explicitly configured, allowlisted host; do not use it unless that
  disclosure is acceptable. `ThreatIntelClient.from_environment()` uses the
  `GLOBALBAN_TI_*` variables, but `.env` files are not loaded automatically.
  Redirects are rejected and results never trigger actions automatically.
- `evaluation/metrics.py` computes descriptive classification and binary
  metrics only when the caller supplies labeled expected and predicted values.
  The checked-in Windows
  manifest documents synthetic parser fixtures, not real EVTX files or an
  executed Atomic Red Team evaluation. `evaluation/atomic_catalog.py` can also
  read a local, operator-supplied Atomic metadata CSV for catalog summaries;
  it never downloads or executes Atomic tests.

## Privacy and AI advisory

AI requests are opt-in through `PrivacyProxy` and require an explicitly
configured HTTPS privacy-proxy endpoint. Requests to the two supported model
provider hosts are rejected by the client to prevent proxy bypass. The proxy
server (`python -m globalban.proxy`) requires TLS certificate/key files, a
client bearer token, and an upstream API key from environment variables. It
accepts only the minimized advisory schema, rejects redirects, and sends its
own fixed system prompt and provider credential; it never forwards a
client-supplied Authorization header. The egress check masks IPv4 to `/24`,
masks IPv6 to `/48`, rounds times to the hour, and rejects unknown fields.
Windows advisory payloads include only event IDs, a score, confidence and
counts—never host names, usernames, process names, raw event fields, or
evidence IDs. AI output is untrusted and advisory-only; no tools, commands, or
policy decisions can be invoked through it. `.env` files are not loaded
automatically.

The WhatsApp notifier is disabled unless explicitly constructed and
`send_alert(alert)` is called with configured Twilio credentials. It sends only
the masked alert summary, uses HTTPS, rejects redirects, and never sends raw
logs or evidence identifiers. `.env.example` lists optional variable names;
the application does not load `.env` automatically.
The `agent` router exposes read-only alert summaries, privacy-filtered
payloads, and optional local-feed lookups. Its static planner/catalog lists
12 allowlisted investigation capabilities; it never imports or executes a
tool based on event/AI text. The action-related catalog entries require
approval and are not wired to execution handlers.

## Policy and firewall actions

The sample configuration is in `config/config.example.yaml` (JSON syntax, which
is a YAML 1.2 subset, parsed with the standard library). Defaults are
`dry_run: true` and `execution_enabled: false`. A block request is checked at
the action boundary for a valid globally routable address, configured IP/CIDR
allowlist, minimum evidence threshold, rate limit, and explicit operator
approval. The local dashboard intentionally exposes no block button.

Real firewall operations are disabled unless an operator deliberately changes
both configuration flags and calls the action API with `approved=True`. The
implementation uses only fixed `netsh advfirewall` argument lists with
`shell=False`; it never executes commands supplied by AI or log content.
Every decision is recorded in a local JSONL audit file with a hash-linked
record chain; the recent action rate limit is restored from that audit trail
after restart. `BlockIPAction.rollback(..., approved=True)` removes only the
deterministically named GlobalBan rule and is also disabled in dry-run mode.
Use an elevated Windows process only if you have separately reviewed and
approved that explicit configuration; this repository does not enable it.

## Configuration

Copy `config/config.example.yaml` and pass it with `--config`. Supported keys:

- `failure_threshold` (minimum 2; default 5)
- `correlation_window_seconds` (default 300)
- `max_actions_per_hour` (default 3)
- `allowlist` (IP addresses or CIDR networks)
- `baseline_path` (local JSON path or `null`)
- `windows_baseline_path` (local JSON path or `null`)
- `baseline_warmup_events` (positive integer; default 20)
- `windows_event_channels` (channels used only with explicit `--windows-live`;
  defaults to `["Security"]`)
- `dry_run` (default true)
- `execution_enabled` (default false)

Unknown keys and invalid types are errors. No credentials belong in this file.

## Tests

Run the standard-library test suite from the repository root:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

Tests use synthetic addresses/data and mock OS/network operations. They never
change firewall settings, query a real Windows Event Log, or contact external
AI/threat-intelligence/notification services. Proxy integration tests use
loopback only and mock the upstream provider.

## Project modules and fixtures

- `app.py` starts the desktop dashboard; `main.py` provides dashboard, batch,
  and explicitly opted-in live SSH/Windows input.
- `proxy.py` provides both the privacy-checked advisory client and a TLS,
  authenticated egress proxy server.
- `actions/enforcer.py`, `policy/gate.py`, and `audit/rollback.py` delegate to
  the existing guarded and audited action boundary.
- `ingestion/windows_source.py` reads XML exports by default and can poll
  configured Windows channels only with the explicit live CLI option.
- `agent/router.py` creates static investigation plans from normalized events;
  `agent/tools.py` contains the 12-name catalog and approval-aware registry.
- `datasets/windows_events.xmll` and
  `datasets/atomic_evtx_manifest.json` are synthetic parser fixtures. No
  binary EVTX artifact is included.