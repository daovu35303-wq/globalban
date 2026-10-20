# SSH datasets

This directory contains JSON Lines (`.jsonl`) data for the Globalban project:

- `ssh_examples.jsonl`: synthetic examples that an AI component may reference.
- `ssh_eval.jsonl`: synthetic examples reserved for evaluation. Do not include
  these records in prompts, training examples, or tuning data.
- `windows_events.xmll`: synthetic Windows Event XML export (the `.xmll`
  extension is retained to match the project fixture layout).
- `atomic_evtx_manifest.json`: metadata for the synthetic XML fixture. It does
  not claim that an EVTX binary file is present or that Atomic Red Team tests
  were executed.

The evaluation module can summarize an operator-supplied Atomic metadata CSV
with `load_atomic_techniques(path)`. That CSV is not included in this project;
check its license and provenance before using it. The loader reads metadata
only and does not download or execute tests.

## Record format

Each line is one JSON object with:

- `event_id`: unique identifier within its file.
- `log`: SSH authentication log message.
- `label`: expected event category.
- `source`: data provenance. The starter records use `synthetic`.

Starter labels:

- `failed_login`: one failed authentication attempt.
- `successful_login`: a successful authentication.
- `multiple_failed_logins`: a log message reporting multiple failures.

## Provenance and privacy

All records currently in these files are fabricated examples, not copied from
real machines or a third-party dataset. The IP addresses use the documentation
ranges reserved by RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, and
`203.0.113.0/24`); they are not intended to identify real clients.

If adding real log data later, document its source, license or permission,
collection method, and any anonymization performed before committing it. Do
not put credentials, personal information, or unmasked production logs here.
The Windows fixture uses only documentation IP ranges and synthetic usernames.
It is not a captured Windows event log and contains no real host information.

## Creating and evaluating data

1. Add one valid JSON object per line and keep the field names consistent.
2. Use a unique `event_id` in each file and assign labels according to the
   definitions above (extend this list when introducing a new label).
3. Put only reference examples in `ssh_examples.jsonl`.
4. Keep `ssh_eval.jsonl` separate and do not use its records to build or tune
   prompts. Use it only to measure behavior against the expected `label`.
5. Validate new entries as JSON and check for duplicate IDs and unexpected
   labels before using the files.
