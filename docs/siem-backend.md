# TASK-004: SQLite backend and AI anomaly alerts

This local backend integrates the existing saved TASK-003 model with durable
prediction and alert history. It does **not** train or modify the model. The
model determines anomaly labels; ordinary application logic creates a security
alert only for AnomalyLabel == -1. An alert denotes unusual SSH behavior, not a
verified attack. No detection accuracy is claimed.

## Kali Linux commands

From the repository root, using your existing trusted TASK-003 model artifact:

```bash
git fetch origin
git switch task-004-siem-backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q

python -m mini_siem.backend init --database data/mini-siem.db

python -m mini_siem.backend ingest \
  --database data/mini-siem.db \
  --input "$HOME/siem-private/ssh/ssh_baseline_features.csv" \
  --model models/ssh-isolation-v1.joblib \
  --batch-id ssh-baseline-v1 \
  --trust-model

python -m mini_siem.backend stats --database data/mini-siem.db
```

Run the same ingest command again to verify idempotency. For an unchanged input,
batch ID, and model artifact, the second result reports zero inserted predictions
and zero inserted alerts. Existing IDs, scores, and processing timestamps stay
unchanged. Normal/Anomaly counts describe that model/batch inference, while
`inserted_predictions` and `inserted_alerts` count only new database rows.
Statistics count all stored versions and batches, not unique people or attacks.
CLI output contains counts and batch/model identifiers, not IPs or raw messages.
Do not put sensitive information in a batch ID.

Use a new batch ID for a new source batch. Reusing an existing ID for different
CSV bytes is rejected without database changes. Choose a new path to create a
separate database. `init` is repeatable on a supported initialized database;
ingestion and statistics require initialization and never silently create a
missing database. Initialization rejects unrelated databases, unsupported schema
versions, and existing empty files. Exit code 0 means success; 2 means failure.
Parent directories are created by `init`. If failed initialization leaves an
empty file, preserve it and choose a fresh database path for the next attempt.

All paths are configurable. There is no new dependency; SQLite is in the Python
standard library. Kali VM execution and real-data ingestion remain pending in
the cloud: no real CSV or trained local artifact was available. Do not run a
training command just to use this backend; supply your already-created model.
Synthetic tests create their own small model fixtures solely for testing.

**Only load model artifacts you created and trust.** Joblib can execute code
while deserializing. `--trust-model` is an explicit trust declaration, not a
sandbox. Existing TASK-003 schema and Scikit-learn compatibility checks still
apply; use an environment matching the artifact's Scikit-learn version.

## Schema

Schema version 1 is recorded in SQLite `user_version`. There is no migration
framework in this proof of concept; unsupported versions are rejected.

| Table | Purpose and key fields |
| --- | --- |
| ingestion_batches | batch_id primary key, source_sha256, record_count, created_at_utc |
| security_events | Reserved for future normalized event ingestion: event_id, batch_id foreign key, source_record, nullable source_ip/event_type/occurred_at, ingested_at_utc |
| predictions | prediction_id, batch_id foreign key, model_id, source_record, source_ip, anomaly_label/status/score, score_convention, processed_at_utc |
| alerts | alert_id, unique prediction_id foreign key, alert_type, created_at_utc |

`security_events` remains empty during feature ingestion. Feature rows are
aggregates, not original events. The reserved `occurred_at` field stays NULL when
no original timestamp is available; no year, event time, or aggregation window
is invented. All newly generated processing timestamps are timezone-aware UTC
ISO 8601 strings ending in `+00:00`. These are processing times, not original log
timestamps. A successful ingestion uses one processing timestamp for its new
batch, predictions, and alerts. Failed attempts are not retained as batches.

The model identifier is `sha256:` plus the hash of the exact serialized artifact
bytes. It identifies an artifact version, not a file path or a measured model
quality. The model is loaded from that same in-memory byte snapshot. A changed
artifact has a new identifier and may add a new prediction/alert history under
the same batch. Re-serializing an otherwise equivalent model can change its hash.

The source hash binds a batch to the exact CSV bytes. Formatting, newline, row
order, or extra-column changes therefore count as changed source content even
if selected numerical features are equivalent. The input is snapshotted once;
a private temporary CSV allows reuse of the existing strict loader and is
removed automatically after validation. Original files are never written.
Concurrent edits after snapshot capture do not change that ingestion's content.
No filesystem paths or raw CSV records are stored in the database.

`source_record` is the one-based CSV data-record position, excluding the header;
quoted multiline records count once. It is not an original event ID or line
number. Repeated IPs or identical rows at different positions are distinct source
records. Call TASK-002 to review unintended duplicate source data beforehand.

The prediction uniqueness key is `(batch_id, model_id, source_record)`. Alerts
are unique by prediction_id, which enforces the same batch/model/source-record
identity. An alert joins its prediction and batch to retrieve SourceIP, model
identifier, score convention, and source hash. Different batch IDs intentionally
create separate histories even for identical bytes; this is not global duplicate
content suppression. The caller is responsible for reusing a stable batch ID
when retrying the same logical batch.

## Validation, inference, and transactions

The backend reuses TASK-003 `load_features`, `load_model`, and `predict_records`.
The same five numerical features are validated and selected; SourceIP and
previous labels/scores/risks are never model inputs. No fit or preprocessing
refit occurs. Scores retain the existing `decision_function` convention: below
zero = Anomaly, zero or above = Normal. No RiskLevel or verified attack label is
invented.

Validation and inference complete before database writes. `BEGIN IMMEDIATE`
serializes writers; a single transaction inserts the batch, predictions, and
alerts. All externally supplied SQL values use bound parameters. Foreign keys,
unique keys, label/status/score sign checks, and an anomaly-only alert trigger
provide database safeguards. Duplicate conflicts use targeted `DO NOTHING`,
never `REPLACE` or updates. Normal predictions are stored but cannot generate
alerts through the application or direct inserts. Transactions roll back on
failure, including partial prediction/alert insertion. Successful prior batches
are retained. Concurrent retries cannot create duplicate predictions or alerts.
Reruns still perform inference; they do not skip validation or trust checks.

## Modules and Python API

- `mini_siem/storage/sqlite.py`: schema initialization, connections, UTC clock, statistics.
- `mini_siem/ingestion/ssh_backend.py`: validation, trusted inference, atomic batch persistence.
- `mini_siem/alerts/management.py`: insert one alert for a stored anomaly.
- `mini_siem/backend.py`: init/ingest/stats CLI.

```python
from mini_siem.storage.sqlite import initialize_database, stored_statistics
from mini_siem.ingestion.ssh_backend import ingest_features

initialize_database("data/mini-siem.db")
result = ingest_features(
    "data/mini-siem.db",
    "/path/to/ssh_baseline_features.csv",
    "models/ssh-isolation-v1.joblib",
    "ssh-baseline-v1",
    trusted=True,
)
print(result)
print(stored_statistics("data/mini-siem.db"))
```

## Limitations and privacy

Databases contain sensitive IP-level prediction history. Keep the database,
SQLite sidecar files, original datasets, model artifacts, and outputs local;
existing Git ignore rules cover databases, `data/`, `models/`, and `reports/`.
Do not force-add them. Copy a live SQLite database using SQLite's backup tools
rather than copying only the main file during writes. No retention policy,
alert acknowledgement workflow, remote notification, authentication, dashboard,
or live log ingestion is included. SQLite here is a small local proof of concept.

Model thresholds and a small baseline do not establish attack classification or
real-world detection accuracy. Tests use synthetic data and verify persistence,
label-driven alerts, idempotency, concurrent retries, history preservation,
validation, trust, and transaction rollback. No real-data results are invented.

## Validation evidence

On Python 3.12 in the cloud, the full suite passed **123 tests** (93 existing and
30 backend tests). Dependency and Git whitespace checks passed. A separate CLI
run using an already-created synthetic test model stored 30 predictions
(27 Normal, 3 Anomaly), created 3 alerts, and retained zero raw security events.
Repeating the exact ingestion added zero predictions and zero alerts. Source CSV
and model hashes were unchanged; temporary demo files were removed. These are
synthetic software checks, not real dataset results or detection accuracy.
