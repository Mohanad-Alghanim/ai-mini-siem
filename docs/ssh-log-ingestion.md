# TASK-006: Historical SSH event ingestion and feature review

This pipeline processes historical structured CSV files, not live logs. It parses
observable evidence, exports IP-level features, optionally compares a baseline,
and stores every validated original event locally. It never loads, predicts with,
replaces, or trains an AI model. Real private datasets are unavailable in the
cloud. Subsequent recorded Kali review found 2,000 events, 1,647 attributed
events, 353 unassigned events and 22 IPs with baseline differences. These are
external observations; legacy compatibility remains not demonstrated.

## Exact Kali Linux commands

From the repository root, using Python 3.10+:

```bash
source .venv/bin/activate
python -m pytest -q
```

Inspect/parse events and create Markdown/JSON reports without exporting features:

```bash
python -m mini_siem.ssh_logs inspect \
  --input "$HOME/siem-private/ssh/OpenSSH_2k.log_structured.csv" \
  --report-dir reports/ssh-raw-inspection
```

Export features and optionally compare the original baseline in one command:

```bash
python -m mini_siem.ssh_logs inspect \
  --input "$HOME/siem-private/ssh/OpenSSH_2k.log_structured.csv" \
  --features data/ssh-observed-features.csv \
  --baseline "$HOME/siem-private/ssh/ssh_baseline_features.csv" \
  --report-dir reports/ssh-feature-review
```

Omit `--baseline` for feature engineering alone. Paths are configurable. The
report directory contains `summary.json` and `analysis.md`; comparison reports
include IPs and must remain private. Existing output files and input/output
collisions are rejected. Use fresh paths for each review run. Feature CSVs have
only SourceIP and the five behavioral columns; no predictions are generated.
A file with no supported IPs exports a header-only feature CSV, not invented IPs.
Such a file is not a valid model inference input.

For event persistence, first review the additive schema proposal below and back
up your database using SQLite backup tooling. Explicitly install the extension
on your existing initialized TASK-004 database, then ingest:

```bash
python -m mini_siem.ssh_logs prepare-storage --database data/mini-siem.db

python -m mini_siem.ssh_logs ingest \
  --database data/mini-siem.db \
  --input "$HOME/siem-private/ssh/OpenSSH_2k.log_structured.csv" \
  --batch-id openssh-historical-v1

python -m mini_siem.backend stats --database data/mini-siem.db
```

Retry the exact ingest command: zero additional events should be inserted. Use
a new batch ID for changed bytes or a deliberately new parser run. If starting
with no backend database, initialize separately with the existing backend CLI;
raw ingestion and extension preparation never create a database silently.
CLI exit 0 means the requested operation completed, **not** model compatibility;
2 means invalid input, identity conflict, output or database failure. Missing
columns, malformed records, or an invalid baseline abort before any event writes.
Inspection and ingestion are separate commands: ingestion validates the raw CSV
but does not use or modify a baseline/features export.

No new dependencies or system packages are needed. The existing dashboard can
be started normally, then refreshed to see the new raw event count. Prediction
and alert counts remain unchanged. No cloud real-data results are claimed.

## Accepted input and preservation

Required headers are exactly LineId, Date, Day, Time, Component, Pid, Content,
EventId and EventTemplate. Additional columns are retained in the local original
record JSON. The shared CSV loader rejects malformed field counts, duplicate or
empty headers, invalid UTF-8, and broken quoting. Empty input is rejected. Every
row needs a positive integral LineId, nonblank Content, and at least one nonblank
EventId/EventTemplate. Original strings are retained; duplicate LineIds are
reported, not dropped. Other original fields may be blank and are not repaired.

Expected size is 2,000 records; a differing size is reported, not silently forced
or filled. Date/Day/Time remain original strings. No timestamp or year is parsed
or invented, and no aggregation time window is assumed. A byte snapshot ensures
the hash, validation and processing refer to the same input. A private temporary
CSV enables reuse of the existing loader and is removed automatically. Original
CSV files are opened for reading only.

## Parser contract: ssh-historical-v2

Supported remote-peer contexts are case-insensitive `from IP`, `rhost=IP`, and
`closed by IP`. The address token must be a complete valid IPv4/IPv6 address;
IPv6 is canonicalized. Version 2 additionally accepts a strictly valid dotted
IPv4 address followed by exactly one terminal separator colon in the `from IP:`
context, as in `Received disconnect from 192.0.2.10: 11: Bye Bye [preauth]`.
The unmodified token is validated first. Only when that fails, and only in the
`from` context with an exact dotted-IPv4-plus-colon shape, is one separator
removed before strict IPv4 validation. Invalid octets and leading-zero octets
remain rejected. This exception does not apply to `rhost=` or `closed by`.

Meaningful IPv6 syntax is never stripped: valid `2001:db8::` remains valid, while
an invalid `2001:db8::1:` is rejected rather than repaired. Bracket/port-suffixed
tokens, multiple separator colons, hostnames, reverse-DNS lookups, embedded address
strings, or other formats are not guessed into a SourceIP. This deliberately conservative rule may miss real peers.

- `supported_peer`: exactly one distinct valid address and no invalid peer tokens.
- `ambiguous_peer`: more than one distinct valid peer address; SourceIP is NULL.
- `invalid_peer`: at least one supported context has an invalid address token;
  SourceIP is NULL even if another token is valid.
- `unsupported_ip_context`: a valid address token exists outside the supported
  peer contexts; it is not assigned as SourceIP.
- `no_ip_evidence`: no usable peer or standalone IP evidence was found.

These are parsing outcomes, not security classifications. Unsupported pattern
reports group outcomes by original EventId (or a template-only marker) and counts;
they do not export raw message examples or templates.
Rows without SourceIP stay in event storage. No usernames are extracted or
invented. Full Content and original fields are retained only in the local
optional details table, not printed by the CLI.

Authentication flags are independent textual indicators:

- FailedAuth: Content begins with `Failed password/publickey/keyboard-interactive/
  none/hostbased`, or contains `authentication failure` (case-insensitive).
- InvalidUser: contains the phrase `invalid user` (case-insensitive).
- AcceptedAuth: Content begins with `Accepted password/publickey/keyboard-interactive/
  none/hostbased` (case-insensitive).
- AuthAmbiguous: both FailedAuth and AcceptedAuth are observed in one message.

These flags are not verified outcomes. Failed reverse mapping or arbitrary uses
of the word "failed" do not automatically become authentication failures.
An original event reference is the CSV data-record position plus original LineId;
the original EventId/template are also preserved. Event type is `id:` + EventId,
or `template:` + EventTemplate if EventId is blank. Prefixes prevent collisions
between IDs and templates. A row lacking both is rejected rather than invented.

## Feature rules: ssh-observed-peer-features-v1

All features cover the supplied file as a whole. Group only records with a
`supported_peer`, by canonical SourceIP. Do not deduplicate source rows or infer
features for missing baseline IPs.

| Feature | Exact formula |
| --- | --- |
| EventCount | Number of supported-peer rows for that IP |
| UniqueEventTypes | Number of distinct derived EventType strings for those rows |
| FailedAuthCount | Number of those rows with FailedAuth true, at most once per row |
| InvalidUserCount | Number of those rows with InvalidUser true, at most once per row |
| FailedAuthRate | FailedAuthCount / EventCount |

A failed authentication mentioning an invalid user increments both counters;
these categories are not disjoint and must not be added as a total event count.
An ambiguous accepted/failure message retains both flags and contributes once
to FailedAuthCount. The ambiguity is reported for review, not resolved into a
verified outcome. AcceptedAuth is retained for inspection but is not a sixth
model feature. IP-less events contribute to overall report indicators, not to
any IP feature vector. Every generated rate is in [0, 1].

## Baseline comparison and model safety

The optional baseline uses the existing TASK-003 feature validator. Comparison
canonicalizes baseline IPs, reports matching IP counts, baseline IPs lacking
generated features, generated IPs absent from baseline, and per-IP/per-feature
value differences. Duplicate baseline IPs are reported as ambiguous and excluded
from value comparisons, never arbitrarily joined. Count comparisons are exact;
rate comparisons tolerate only floating point roundoff up to 1e-12. Reports
include extraction coverage and unsupported parsing outcomes.

The earlier findings (1,145/2,000 events with IP evidence and 27/30 baseline IPs
represented) are external observations to investigate, **not expected values to
force**. Actual reports use only the provided files. Parser scope, original
aggregation rules, unobserved IPs, template counting, duplicates, and aggregation
windows can all explain differences. No new real-data comparison was performed
in the cloud.

Even an exact numerical match is not proof of compatible feature semantics.
The original training pipeline's feature definitions/window must be independently
confirmed and reviewed. Every generated report therefore records
`model_compatibility.status = not_demonstrated` and `inference_allowed = false`.
There is no model input argument or inference route in these commands; the
`require_model_compatibility` guard refuses inference for this unverified feature
version. Do not pass these exports to the TASK-003/004 inference commands until
Project Manager review establishes compatibility. Do not retrain or replace a
model to force agreement. No attack accuracy metrics are calculated.

## Explicit additive storage extension

The existing security_events table holds batch identity, source record, IP,
event type and processing timestamp. It cannot preserve original LineId, raw
Content, partial Date/Day/Time, template or parser outcomes. Silently dropping
those essential fields would lose provenance. The implemented minimal extension is
one child table, installed **only** by the separate `prepare-storage` command:

```sql
CREATE TABLE ssh_event_details (
    event_id INTEGER PRIMARY KEY REFERENCES security_events(event_id),
    parser_version TEXT NOT NULL,
    original_fields_json TEXT NOT NULL,
    parse_status TEXT NOT NULL,
    failed_auth INTEGER NOT NULL CHECK(failed_auth IN (0,1)),
    invalid_user INTEGER NOT NULL CHECK(invalid_user IN (0,1)),
    accepted_auth INTEGER NOT NULL CHECK(accepted_auth IN (0,1)),
    auth_ambiguous INTEGER NOT NULL CHECK(auth_ambiguous IN (0,1))
);
```

This is an optional extension, not a silent ingestion migration. The original
four tables, constraints and core schema user_version 1 remain unchanged, keeping
TASK-004/005 compatible. The details table's parser_version identifies the
parsing contract. Preparation is transactional and repeatable; incompatible
pre-existing extension columns are rejected. Ingestion refuses absent extensions.
No migration is applied to a real database by this development task.

A single BEGIN IMMEDIATE transaction stores a batch, all security_events and
all details. Batch IDs are bound to the exact source hash and row count. Stable
one-based CSV data-record positions prevent duplicates (including quoted
multiline records); duplicate original LineIds do not change those identities.
Retries preserve original ingest timestamps and details. Existing batches from
other workflows are not repurposed. SQL values use bound parameters. Any storage
failure rolls back all changes; original predictions/alerts are never written.
Only new ingested_at_utc processing timestamps are generated. occurred_at is
NULL, because the historical input does not establish full event timestamps.

## Privacy and limits

Local databases now contain raw SSH messages, identifiers and partial timestamps.
Protect database copies and SQLite sidecars accordingly. Reports with baseline
comparisons contain IP identifiers; feature exports also contain IPs. Keep all
these files in ignored data/ or reports/ directories, and never force-add them.
The CLI prints counts/compatibility status only. Reports do not reproduce raw
messages or usernames. Synthetic test fixtures are generated in temporary paths.

No live monitoring, new attack scenarios, dashboard changes, threshold changes,
alert generation or model training is included. This in-memory historical-file
pipeline is intended for the small project dataset, not unbounded production logs.

## Validation evidence

On Python 3.12 in the cloud, **187 tests passed**: all 153 existing tests and 34
historical ingestion tests. Dependency and Git whitespace checks passed. Tests
cover strict loading, supported/absent/ambiguous IPs, overlapping indicators,
feature formulas, duplicate source IDs, baseline differences/duplicate keys,
model compatibility blocking, explicit extension preparation, transactional
rollback, concurrent retries, unchanged historical predictions/alerts, and
continued dashboard queries after raw ingestion.

A separate synthetic CLI review exported 3 IP feature rows from 6 events:
4 with supported peer evidence, 2 without. All 6 events were persisted, a retry
inserted zero, and original input bytes were unchanged. The report kept inference
blocked. Temporary demonstration files were removed. These are synthetic checks,
not the real dataset's coverage or feature results.

## Historical parser correction: v2 review (merged in PR #6)

The supplied real-data review identified the separator formatting in 413 E24
and 45 E7 messages. Those are external observations, not measured results of this
cloud correction. Do not assume that 458 records will become supported: another
invalid/ambiguous peer in the same message could still block extraction. The
correction changes only peer normalization. Feature formulas, model thresholds,
AI compatibility guards and event storage/idempotency logic are unchanged.
The report and new stored details identify `ssh-historical-v2`.

To regenerate reports at guaranteed fresh local paths, from the repository root:

```bash
source .venv/bin/activate
python -m pytest -q
mkdir -p reports
ssh_review_dir="$(mktemp -d reports/ssh-parser-v2-XXXXXX)"
python -m mini_siem.ssh_logs inspect \
  --input "$HOME/siem-private/ssh/OpenSSH_2k.log_structured.csv" \
  --baseline "$HOME/siem-private/ssh/ssh_baseline_features.csv" \
  --features "$ssh_review_dir/features.csv" \
  --report-dir "$ssh_review_dir"
```

Compare against the saved **v1** report (change the first path to your actual
previous report). This prints counts and per-feature gap summaries without IPs:

```bash
ssh_previous_report="reports/ssh-feature-review/summary.json"
python - "$ssh_previous_report" "$ssh_review_dir/summary.json" <<'PY'
import json
import sys

old, new = [json.load(open(path, encoding="utf-8")) for path in sys.argv[1:]]
print("Metric | previous | corrected")
for name, getter in (
    ("Total events", lambda r: r["events"]),
    ("Supported peer events", lambda r: r["events_with_source_ip"]),
    ("Invalid peer events", lambda r: r["parse_status_counts"].get("invalid_peer", 0)),
    ("Generated IP records", lambda r: r["generated_ip_records"]),
):
    print(name, getter(old), getter(new), sep=" | ")

def gaps(report, feature):
    comparison = report.get("baseline_comparison")
    if comparison is None:
        return "comparison not performed"
    values = [abs(row["differences"][feature]["generated"] - row["differences"][feature]["baseline"])
              for row in comparison["feature_differences"] if feature in row["differences"]]
    return {"differing_shared_ips": len(values), "maximum_absolute_gap": max(values, default=0)}

for feature in ("EventCount", "UniqueEventTypes", "FailedAuthCount", "InvalidUserCount", "FailedAuthRate"):
    print(feature, gaps(old, feature), gaps(new, feature), sep=" | ")
for label, report in (("previous", old), ("corrected", new)):
    comparison = report.get("baseline_comparison")
    if comparison is not None:
        print(label, "matching IPs:", comparison["matching_source_ips"],
              "baseline IPs without generated features:", len(comparison["baseline_ips_without_generated_features"]),
              "generated IPs absent from baseline:", len(comparison["generated_ips_not_in_baseline"]),
              "numerical_match:", comparison["numerical_match"])
print("Existing-model inference allowed:", new["model_compatibility"]["inference_allowed"])
PY
```

The new Markdown/JSON report contains detailed per-IP, per-feature generated and
baseline values. Zero gaps on shared IPs do not account for unmatched/ambiguous
baseline IPs; review those lists too. Keep reports private. Improved extraction
or even `numerical_match: true` does not demonstrate full semantic compatibility
or permit automatic inference. The supplied later Kali counts are attributed above. A fresh before/after
comparison still requires the actual saved reports; this audit does not invent
per-feature deltas from unavailable private files.

No storage migration is needed for the parser correction. Existing v1 event
batches remain unchanged. The existing parser-version conflict check deliberately
rejects re-ingestion into a v1 batch ID. Prefer report-only review first. If a
separate v2 event history is intentionally desired after review, use a new batch
ID (for example `openssh-historical-v2`); this adds another batch and its event
rows, so total raw-event counts include both histories. Retrying that same v2
batch remains idempotent. Do not delete or overwrite the v1 history.

Correction validation (Python 3.12 cloud): **214 tests passed**, including all
187 prior tests and 27 new regressions. The historical-ingestion subset passed
61 tests. Regression coverage includes representative synthetic E24/E7 disconnect
messages, malformed octets/tokens, hostnames, meaningful IPv6 trailing colons,
IPv6 invalid suffixes, ambiguous peers, original-content preservation, idempotent
v2 retries, v1 history/version conflicts, and unchanged inference blocking.
Dependency and Git whitespace checks passed. The documented before/after
comparison script was exercised with temporary synthetic report fixtures.
The later Kali observations are 1,647 supported-peer events out of 2,000,
30 matching generated/baseline IPs and 22 IPs with at least one difference.
Those supplied results supersede the earlier coverage observations, not the
research caveat: inference on generated features is still blocked.
