# Local Mini SIEM dashboard

This is the local TASK-012 view combined with PR #14 operating guidance. The
working changes are uncommitted/unpublished; do not replace this checkout with
main and expect the same UI. No additional validation was run in consolidation.

The dashboard is a read-only, offline SSH proof of concept. It never loads an AI
artifact, trains a model, runs inference, creates alerts or updates SQLite records.
Use the existing trusted environment and database from the repository root:

```bash
cd ~/ai-mini-siem
source .venv/bin/activate
export MINI_SIEM_DATABASE="$PWD/data/mini-siem.db"
python -m streamlit run mini_siem/dashboard/app.py \
  --server.address 127.0.0.1 --server.port 8501 \
  --browser.gatherUsageStats false
```

Open http://127.0.0.1:8501 in Kali and stop with Ctrl+C. The dark theme and
localhost-only default are unchanged. There is no application authentication;
do not expose the service publicly. No private database is distributed in Git.
Missing/incompatible databases produce a safe message, not a new database.

## Four analyst pages

| Page | Contents |
| --- | --- |
| Overview | Stored prediction/Normal/Anomaly/alert/event counts, classification distribution, display-priority counts and UTC processing-day totals |
| Security Events | Stored event type, Source IP, available peer-parse status, original timestamp and ingestion timestamp; separate sanitized native evidence tab |
| Alerts | Alert Name, Source IP, Risk Level, alert creation timestamp and brief description |
| Predictions | Source IP, unchanged Normal/Anomaly classification, display Risk Level and prediction processing timestamp |

The former Data Sources / System Information page, SQLite path input and all
batch/model selection widgets are removed. Technical model hashes, batch IDs,
primary keys and numerical anomaly scores are not displayed in tables/charts.
Database selection uses MINI_SIEM_DATABASE outside the UI, defaulting to the
existing data/mini-siem.db path. Relevant limitations remain in the shared
“How to interpret these results” expander.

Refresh and widget interactions reread stored data; there is no polling or live
AI detection. Overview counts remain global, while table filters affect only the
selected table. Multiple stored observations can refer to the same IP; hiding
internal IDs does not deduplicate or merge their history.

## Date/time and combined filters

Available full timezone-aware timestamps are converted to UTC and shown as
**YYYY-MM-DD HH:MM:SS**. Missing, partial, invalid or timezone-ambiguous times are
**Unknown**. Original years, timezones and event times are never inferred from
historical Date/Day/Time strings. UTC processing-day chart buckets remain dates,
not invented midnight event timestamps.

- Alerts use actual alert creation time, not prediction time substituted for it.
- Predictions use stored prediction processing time.
- Security Events shows original time separately from ingestion time. The date
  control explicitly selects which one to filter; historical original time is
  often Unknown even when ingestion time exists.
- Native sanitized evidence has no trusted original event time; it shows Unknown.

Source IP and Alert Name/Event Type searches are literal, case-insensitive
substrings. Risk and available status/classification choices are exact filters.
Date ranges are inclusive UTC days; one selected date means that whole day.
All controls combine with AND. Unknown times remain visible without a date
filter and are excluded when a date filter is active. Raw events do not have
model risk scores, so no risk is inferred by joining unrelated IP predictions.
Native evidence offers only its available evidence-category filter.

## Event ID investigation

The schema defines security_events.event_id as an INTEGER PRIMARY KEY. Ingestion
assigns it through SQLite and preserves source_record independently. Query code
reads that primary key directly; no mapping defect was found in this code review.
Private Kali IDs were not inspected or regenerated.

The analyst-facing table now hides Event ID, Batch ID and Source Record, and
shows the existing Event Type plus available peer-parsing Event Status. Event
Type may be a historical identifier such as id:E24; it is not an attack name.
Status comes from the optional existing ssh_event_details table. If no detail
exists it is Unknown. That table is never created or changed by the dashboard.
All primary keys and stored source values remain intact. Gaps in primary keys
are not corrected, renumbered or treated as evidence loss.

## Risk Level: transparent presentation only

The repository's dataset-analysis risk policy is illustrative/configurable; no
validated compatible risk policy is stored in the prediction/alert schema. The
separate historical risk CSV is not adopted as ground truth or joined into the
UI. The following fixed display mapping uses the already stored decision score:

| Risk Level | Rule |
| --- | --- |
| High | score < -0.1 |
| Medium | -0.1 <= score < 0 |
| Low | score >= 0 |

The -0.1 boundary is an **uncalibrated presentation convention**, not a learned
threshold, attack probability, impact estimate or independently verified severity.
High does not mean confirmed attack; Low does not prove safety. Score scales may
differ between model artifacts. No model offset, prediction label, score, stored
alert or feature definition changes. These bins are not the historical CSV's
claimed RiskLevel semantics.

All stored anomaly alerts use the accurate presentation name **Unusual SSH
Authentication Behavior** and a description explaining that the model marked
behavior as unusual. There is no invented SSH Brute Force or other specific
attack classification. Normal predictions stay Low and generate no new alerts;
the dashboard itself generates nothing.

## Privacy and sanitized native evidence

The optional existing MINI_SIEM_LAB_REVIEW variable selects an authorized sanitized
V2 review.json. It is configured outside the UI; no path input or hash identifiers
are shown. The dashboard reads selected summary fields only, not private capture
files/credentials, and does not reverify the original capture. Source/time/risk
values absent from that report are not reconstructed. Correlation stays unresolved;
server evidence is separate from attack labels and legacy-model predictions.
No private Kali evidence was accessed for this dashboard change.

SQLite access retains mode=ro, query_only, integrity/schema checks and safe errors.
Existing SQL filter helpers still use bound parameters; the new analyst controls
filter only small in-memory display frames. Display helpers return copies and
never issue writes. The existing dark theme, dependency set, native laboratory
security controls and legacy model remain unchanged.

## Existing focused validation (not rerun)

```bash
python -m pytest -q tests/test_dashboard.py tests/test_dashboard_presentation.py tests/test_final_demo.py
```

Prior TASK-012 result: **51 focused tests passed**, plus a targeted event-ID
recheck. These are existing results, not a test run of the combined state.
Checks covered UTC display and unknown dates, fixed risk boundaries, combined
literal/date/status filters, unchanged stored scores/IDs/database bytes, all four
pages, hidden technical controls and sanitized report separation. Test data is
synthetic and temporary, not the private Kali database or evidence. The full
suite was not run for the UI-only change. No tests were run for the subsequent
documentation consolidation. The combined state and real Kali/browser acceptance
remain unverified. No detection accuracy or new private-data acceptance result
is claimed.

The [team guide](team-kali-operations.md) covers restart and private handoff;
the [audit](documentation-audit.md) separates historical verification from this
uncommitted consolidation.
