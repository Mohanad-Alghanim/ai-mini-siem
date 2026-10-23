# TASK-005: Local Streamlit Mini SIEM dashboard

The dashboard reads the existing TASK-004 SQLite backend. It never ingests data,
loads an AI artifact, trains a model, or writes predictions/alerts. No demonstration
data is generated in the application. Temporary synthetic records exist only in
automated tests.

## Kali Linux launch commands

Run from the repository root using Python 3.10+ and your existing database:

```bash
git fetch origin
git switch task-005-streamlit-dashboard
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q

MINI_SIEM_DATABASE="$PWD/data/mini-siem.db" \
  python -m streamlit run mini_siem/dashboard/app.py \
  --server.address 127.0.0.1 \
  --server.port 8501 \
  --browser.gatherUsageStats false
```

Open the localhost address printed by Streamlit in the Kali VM's browser.
Stop with Ctrl+C. The checked-in `.streamlit/config.toml` also binds to localhost,
disables usage telemetry, and supplies the dark SOC-inspired theme. There are no
external APIs, integrations, or application telemetry. Streamlit and Plotly were
already dependencies; no new dependency or SQLite migration is needed.

The optional `MINI_SIEM_DATABASE` environment variable selects the initial path.
Without it the default is `data/mini-siem.db`, relative to the launch directory.
You can change the masked database path field in the sidebar. It is only a local
configuration field, not authentication. The application does not show paths in
error messages. Existing database files are required: missing, malformed, empty
uninitialized files, or incompatible schemas produce a safe message rather than
creating a database or printing SQL exception traces.

To inspect counts separately, use the unchanged TASK-004 command:

```bash
python -m mini_siem.backend stats --database data/mini-siem.db
```

The locally reported expected values (30 predictions, 27 Normal, 3 Anomaly,
3 alerts, 1 batch and 0 raw events) are validation references from the project,
**not hardcoded dashboard values**. Actual displayed counts always come from SQL.
No real database was available in the cloud, so confirming those values on your
Kali database remains pending.

## Pages and interactions

- **Overview:** six global KPI cards, Normal/Anomaly distribution, alerts grouped
  by batch and model, score histogram, and UTC processing-date counts.
- **Alerts:** stored alerts joined to predictions, including ID, SourceIP, alert
  type, score, model, batch, processing time and alert creation time. Filter by
  batch/model or use literal SourceIP substring search.
- **Predictions:** stored SourceIP, status, score, batch, model and processing
  timestamp, with Normal/Anomaly, batch/model and SourceIP filters.
- **Data Sources / System Information:** database/table semantics, model identity,
  score conventions, processing-time meaning, and privacy/scientific limitations.

The overview always describes **all stored batches/model versions**; table filters
affect the selected operational table only. Charts and KPIs are not prediction
accuracy metrics. Scores are shown for one selected model artifact at a time;
independently trained artifacts can have different scales and thresholds.
The zero reference line follows the stored TASK-003 decision_function convention:
negative = Anomaly, zero or above = Normal. Scores are not attack probabilities.

**Refresh** reruns the page and reads a new database snapshot. Widget interactions
also rerun the page. Nothing automatically ingests backend data and there is no
automatic polling. There is no cache of database results. Use the separate backend
CLI to add data, then refresh. Each query snapshot uses one read transaction so
its own cards/charts/tables share a consistent database view. On a filter page,
options are read before the selected filtered snapshot; a simultaneous backend
update may appear after the next refresh.

Timezone-aware stored ISO processing timestamps are converted to UTC for day
counts. Invalid or timezone-ambiguous timestamps are skipped with a visible
count; no date, year or timezone is invented. The chart uses bars rather than an
interpolated time series. A single recorded day is explicitly identified as
insufficient for a historical trend. Processing dates are not original event
dates. Missing raw events mean none are stored, not that no SSH activity occurred.

## Query and privacy safeguards

`mini_siem/dashboard/queries.py` opens SQLite with URI `mode=ro` and enables
`PRAGMA query_only`. It reuses TASK-004 schema-version checking and additionally
checks required columns, integrity, foreign keys, classification/score state,
and duplicate/dangling join identities. Unsupported/malformed state is rejected
with a generic safe error. It does not initialize, migrate or repair databases.
All filter values use SQL bound parameters; only fixed program table/column
names are interpolated. SourceIP search treats SQL metacharacters literally.

`mini_siem/dashboard/charts.py` creates Plotly figures from the query results.
`mini_siem/dashboard/app.py` renders the pages and handles safe data errors.
The existing backend and AI prediction code remain unchanged.

IPs appear only in operational alert/prediction tables. No raw log contents are
queried, printed or displayed. The system-information page and global charts do
not show IP values. Database files, model artifacts, datasets and private reports
must remain local and ignored by Git. Tables can be exported by the browser UI;
handle any exports as sensitive data and keep them outside version control.

**Use Streamlit locally only. Do not expose the server publicly without
appropriate authentication and additional security controls.** There is no
application authentication in TASK-005. A local browser interface does not make
the stored records nonsensitive.

## Limits and validation

The model is a 30-record educational proof of concept. Anomaly means unusual
behavior, not a confirmed attack. No accuracy, precision, recall or F1 is shown
without independent labeled ground truth. Counts include separate model/batch
histories, not unique IPs, attacks or incidents. Alert grouping is a summary of
stored alerts, not risk severity. No dashboard inference, real-time log ingestion,
alert modification or additional ML model is implemented.

The current query layer reads the small database in memory and runs integrity
checks on refresh; very large histories would need pagination and more targeted
queries. SQLite read contention/timeouts are handled with the same safe unavailable
message. The existing database's permissions and journal files must permit normal
SQLite read-only access. Unit and Streamlit AppTest checks use initialized temporary
SQLite databases and synthetic records; those tests do not establish real-data
correctness or detection accuracy.

Validation in the cloud (Python 3.12): **153 tests passed** (123 existing and 30
dashboard tests). Coverage includes SQL KPIs/counts, joins, bound filters, empty
and malformed databases, read-only rejection of writes, unchanged database
bytes, timestamp handling, Plotly figures, Streamlit navigation/filtering, and
manual refresh. Dependency and Git whitespace checks passed. A separate local
Streamlit startup/health/HTTP check passed using a synthetic database, whose
bytes remained unchanged. The server was stopped and temporary startup files
removed. No real database values or real-data dashboard validation are claimed.
