# Local Streamlit dashboard

The dashboard reads an initialized local SQLite database and, optionally, a
sanitized V2 native SSH review. It never loads a model artifact, fits a model,
runs predictions, ingests events or writes alerts. TASK-005 introduced the base
screens; merged PR #13 added Security Events and separate native evidence.

## Start, stop and restart on Kali

Use reviewed main and the existing working environment:

```bash
cd ~/ai-mini-siem
source .venv/bin/activate
export MINI_SIEM_DATABASE="$PWD/data/mini-siem.db"
python -m streamlit run mini_siem/dashboard/app.py \
  --server.address 127.0.0.1 \
  --server.port 8501 \
  --browser.gatherUsageStats false
```

Open http://127.0.0.1:8501 in Kali. Stop with Ctrl+C; restart using the same block
in a new terminal. Data is not deleted. `.streamlit/config.toml` also binds to
localhost, disables usage telemetry and sets the existing dark theme.
No external API or authentication service is used. Do not expose the UI publicly.

The local database is not in Git. For a new machine, follow
[first-time installation](../README.md#first-time-installation-on-another-kali-machine)
and explicitly initialize an empty database or obtain an approved project-owned
backup. A fresh clone has no populated demonstration database. Reuse the venv;
do not recreate/upgrade it merely to view the dashboard.

The masked SQLite path field in the sidebar selects another existing database;
it is not authentication. Missing, malformed, empty-uninitialized or incompatible
databases produce a safe error instead of being silently created. The default
path is data/mini-siem.db relative to the repository-root launch directory.

```bash
python -m mini_siem.backend stats --database data/mini-siem.db
```

The Project Manager previously recorded 30 predictions (27 Normal, 3 Anomaly)
and 3 alerts. An earlier feature-only database had 0 raw events; later historical
ingestion recorded 2,000 events. These are observations at particular stages,
not simultaneous universal expectations or hardcoded values. Counts always
come from the selected database; this audit does not read the private Kali DB.

## Screens and filters

| Screen | Contents and controls |
| --- | --- |
| Overview | Six SQL-derived KPIs; Normal/Anomaly distribution; alerts grouped by batch/model; per-model scores and UTC processing-day counts |
| Security Events: stored historical events | Metadata only: event/batch/source record, SourceIP, type and available timestamps; exact batch filter and literal IP substring search |
| Security Events: native SSH lab evidence | Selected sanitized V2 review.json; record/source coverage, evidence-category counts, event references and unresolved-correlation warning |
| Predictions | SourceIP, status, score, batch, model and processing time; Normal/Anomaly, batch/model and literal IP filters |
| Alerts | Joined alert/prediction data with IP, score, batch/model and creation/processing time; batch/model/IP filters |
| Data Sources / System Information | Source separation, score conventions, offline scope, timestamp and model/privacy limitations |

Overview KPIs describe all stored batches/model versions; table filters do not
change them. Counts represent observations, not unique IPs, incidents or attacks.
The score chart selects one model artifact at a time because independent models
can have different scales. `decision_function < 0` is Anomaly; zero or above is
Normal. Scores are not attack probabilities. No accuracy, precision, recall or
F1 is shown without independent labeled ground truth.

Refresh and widget interactions reread the database/report. There is no polling,
continuous ingestion or automatic model execution. Each query snapshot uses a
read transaction; a concurrent backend update may appear on the next refresh.
Timezone-aware processing times support UTC counts. Invalid/ambiguous timestamps
are skipped and reported; missing original years/timezones are not invented.
A single processing day is not a historical trend. Zero stored raw events does
not mean no SSH activity occurred.

## Native evidence report

After an authorized analyst has generated a V2 review and arranged a protected
report-only handoff, select its actual readable path:

```bash
export MINI_SIEM_LAB_REVIEW="$PWD/reports/dashboard-evidence/review.json"
```

Set the variable before launching, or use the masked field in Security Events.
This is an operator-prepared example path, not a shipped file. The dashboard
checks the report's version, counts, references and disabled model/label flags;
it does **not** reverify the root-private capture or independently authenticate
the report. It displays selected sanitized fields only, not arbitrary raw strings.

Follow the [native evidence handoff](final-demonstration.md#prepare-native-evidence-without-exposing-the-capture).
Never chmod/chown the original capture or start Streamlit as root. Missing report
access does not block the database screens. Native event counts are separate
from database event/prediction KPIs. No native record triggers the legacy model.

## Read-only and privacy safeguards

`mini_siem/dashboard/queries.py` opens SQLite with URI mode=ro and query_only,
checks schema/integrity/relationships and validates prediction/score state.
`events.py` uses the same read-only connection for historical metadata and
validates the selected offline evidence report. Filter values are SQL bound
parameters; literal IP searches do not treat SQL metacharacters as wildcards.
The app never initializes, migrates or repairs a database. Error text omits SQL,
private paths and stored values.

IPs appear only in operational historical/prediction/alert tables. Raw message
content is not queried or displayed. Keep databases, backups, sidecars, models,
reports and any browser table exports private and outside Git. A localhost UI
still contains sensitive data and supplies no application authentication.

## Validation and limits

At TASK-005, 153 cloud tests passed, including 30 initial dashboard tests. The
consolidated implementation later passed 427 tests with Streamlit AppTest coverage
of all pages, filters and Refresh, and a loopback HTTP health check. Fixtures are
synthetic, not evidence of attack-detection accuracy. Recorded local Kali figures
are attributed above; private browser/service checks are not independently
repeated by this documentation audit.

The model is a 30-record proof of concept with legacy feature-provenance limits.
Historical prediction replay is offline and does not validate performance on
unseen hosts, time periods or attack types. Native correlation remains unresolved.
The small query layer reads histories into memory; production-scale pagination,
authentication, remote alerts and continuous monitoring are outside this scope.
