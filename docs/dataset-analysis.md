# TASK-002: SSH dataset inspection

This read-only pipeline loads CSVs with Pandas, validates configured contracts,
profiles data quality, inspects SSH authentication indicators, and compares
IP-level records. It does not train a model, repair data, or verify previous
predictions as ground truth. No real datasets were available during development;
all automated fixtures are synthetic and generated in temporary directories.
Real-data analysis remains pending.

## Kali Linux commands

Use the repository root and the TASK-001 Python virtual environment. Python 3.10+
is required; automated validation was performed on Python 3.12 in the cloud,
not directly in a Kali VM.

```bash
git fetch origin
git switch task-002-dataset-analysis
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q
```

Keep the four original files in a private directory, for example
`$HOME/siem-private/ssh`. Do not edit or commit them. The default filenames are:

| Role | Filename | Expected rows from project description |
| --- | --- | ---: |
| events | OpenSSH_2k.log_structured.csv | 2000 |
| baseline | ssh_baseline_features.csv | 30 |
| isolation | ssh_isolation_results.csv | 30 |
| risk | ssh_dynamic_risk_results.csv | 30 |

Run an initial inspection using the minimal contract:

```bash
python -m mini_siem.analysis \
  --data-dir "$HOME/siem-private/ssh" \
  --output-dir reports/ssh-initial
```

A nonzero exit code of **1 is expected** here because complete real schemas have
not been confirmed. This still writes both reports. Inspect `summary.json` for
actual column names, missing values, and quality findings. No columns are created,
renamed, or guessed. Unknown columns are profiled for missing/distinct values;
no unconfirmed type or numerical range is assigned to them.

For full validation, copy the example to an ignored local directory:

```bash
mkdir -p data
cp config/dataset_schema.example.json data/dataset_schema.local.json
```

Edit `data/dataset_schema.local.json` to match the **actual headers and documented
semantics of each of your four files**, then run:

```bash
python -m mini_siem.analysis \
  --data-dir "$HOME/siem-private/ssh" \
  --schema data/dataset_schema.local.json \
  --output-dir reports/ssh
```

Individual paths override `--data-dir` and its default filenames:

```bash
python -m mini_siem.analysis \
  --events "$HOME/siem-private/ssh/OpenSSH_2k.log_structured.csv" \
  --baseline "$HOME/siem-private/ssh/ssh_baseline_features.csv" \
  --isolation "$HOME/siem-private/ssh/ssh_isolation_results.csv" \
  --risk "$HOME/siem-private/ssh/ssh_dynamic_risk_results.csv" \
  --schema data/dataset_schema.local.json \
  --output-dir reports/ssh
```

Reports are `analysis.md` (human-readable) and `summary.json` (structured JSON).
Subsequent runs replace these generated reports. Input/output collisions are
rejected, including resolved symlinks. Input files are opened only for reading.
Exit codes: **0** means no findings in executed checks, **1** means findings,
unavailable inputs, or unconfirmed complete schemas, and **2** means a configuration
or report-writing error. Always inspect skipped checks even when exit code is 0.
Do not interpret exit code 0 as full dataset validity or model correctness.

## Schema and policy configuration

The example is a **provisional minimum contract**, not a description of inspected
real data. It requires SourceIP for IP-level tables; AnomalyLabel and AnomalyScore
for isolation results; and RiskLevel for risk results. These are the only names
provided in the task. The events schema intentionally has no required headers
until you inspect them. The actual files may use different names: edit the
contract rather than modifying the CSVs. Prediction checks use the explicit
AnomalyLabel, AnomalyStatus, AnomalyScore, and RiskLevel headers; alternate
prediction header names are not automatically mapped.

Every role under `datasets` supports:

- `required`: exact expected header names. Missing headers are reported, never added.
- `columns`: per-column rules. A configured rule also makes that column expected.
  Supported `type` values: `string`, `number`, `integer`, `ip`.
  Numeric rules support inclusive `min` and `max`; all rules support `allowed`.
  Blank values are counted separately; nonfinite numbers are invalid types.
- `complete`: set to true **only after confirming the full required schema**.
  This is your declaration, not an automatic certification.
- `source_ip`: actual IP column header (default SourceIP).
- `event_column`: actual event type/identifier header, when available.
- `content_column`: actual SSH message header, when available.

For example, if inspection confirms a count column, declare it as an integer
with a minimum of zero. Do not assign a count field name or arbitrary upper bound
without evidence. Label values, risk vocabularies, and score ranges likewise
require confirmation. No year is inferred from partial timestamps; chronological
and time-window checks are not attempted.

The optional `prediction_policy` object supports three independent conventions.
The following is **an illustrative policy only**, not a finding or a recommended
policy for your existing predictions. Replace it with the original producer's
confirmed definitions; leave it empty when they are unknown:

```json
{
  "label_status": {"-1": "flagged", "1": "normal"},
  "score_rule": {
    "direction": "lower",
    "threshold": 0,
    "anomaly_label": -1,
    "normal_label": 1
  },
  "risk_by_status": {"flagged": ["review"], "normal": ["low"]}
}
```

`score_rule` uses an inclusive boundary: lower means score <= threshold is
anomalous, higher means score >= threshold is anomalous. There is no default
score sign, threshold, or risk/anomaly equivalence. AnomalyScore could come from
different scoring APIs. Label/status, score/label, and status/risk checks report
compared and inconsistent counts; missing columns or policy cause a **skipped**
check. Unknown label/status mappings are reported separately. Declare allowed
categories in column rules to validate the full category domain.

## Relationships and interpretation

All available pairs are compared on valid canonical SourceIP values. Reports show
shared and unmatched IP counts, and differences in common prediction/risk fields.
IP-level tables are expected to have unique keys: duplicate keys are reported
and excluded from field comparisons to avoid arbitrary joins. Repeated event IPs
are normal and are not treated as invalid IP-level keys. Numeric comparisons use
numeric values; status and risk strings use exact spelling. Missing/non-numeric
values are excluded from comparisons and remain visible in quality checks when
the corresponding type rule is configured. Different output values may reflect
intentional processing stages; differences are review candidates, not proof of a
bug. Aggregate feature formulas cannot be verified without their definitions.

For raw event coverage, an explicit IP column is preferred. Otherwise a configured
message column is searched conservatively for SSH `from IP` or `rhost=IP` patterns.
Only valid, unambiguous IPv4/IPv6 evidence is retained transiently. No SourceIP
column is added. Missing IP evidence is counted; it does not prove a bad aggregate.
Message formats outside these patterns are not resolved. Authentication analysis
counts accepted, failed, invalid-user, authentication-failure, and disconnect
text indicators. Categories may overlap; counts are not verified outcomes.
Event type frequencies are exported without the original values to reduce
accidental disclosure. Empty CSVs with a valid header produce zero-row findings;
missing/unreadable files and malformed CSVs are reported per dataset, allowing
other inputs to be analyzed. Duplicate headers and nonrectangular records are
rejected rather than silently rewritten. Literal `NA` is preserved; only null
and whitespace-only cells count as missing.

## Privacy and limitations

Reports export counts, configured column names, and check status; they omit log
messages, IP values, and filesystem paths. Review column names before sharing.
CSV files (including compressed-name variants), `data/`, and `reports/` are ignored
by Git. Do not force-add raw data, derived data, or reports containing sensitive
information. The loader currently supports UTF-8 CSVs (including BOMs), comma
separators, and in-memory inspection suitable for these small datasets. It does
not stream huge files, infer dataset provenance, fabricate timestamps, or evaluate
model accuracy. No real-data report is committed or claimed in this task.
