# TASK-003: Initial SSH anomaly detection engine

This is an educational Isolation Forest proof of concept for a 30-record,
IP-level SSH baseline. It detects unusual behavioral feature combinations;
**anomaly is not verified attack classification**. No production detection
performance is claimed. Real baseline CSVs were unavailable in the cloud during
implementation. The Project Manager later recorded 27 Normal and 3 Anomaly
predictions from the private 30-row original baseline on Kali. These are local
observations, not detection metrics or results remeasured by this cloud audit.
Automated fixtures are synthetic.

## Inputs and validation

The CSV must contain SourceIP and these five numerical features:

| Feature | Validation |
| --- | --- |
| EventCount | Nonnegative integral count |
| UniqueEventTypes | Nonnegative integral count |
| FailedAuthCount | Nonnegative integral count |
| InvalidUserCount | Nonnegative integral count |
| FailedAuthRate | Finite number in [0, 1] |

The shared TASK-002 Pandas CSV loader rejects duplicate headers and malformed
records. The shared validation component checks types/ranges. All six fields
must be present and nonblank. SourceIP must be a valid IPv4/IPv6 identifier.
Feature values must be numeric, finite, and within the model's float32 range.
Invalid inputs are rejected without imputation, clipping, dropped rows, or
source-file changes. Counts such as `2.0` are accepted if numerically integral;
boolean values are rejected. No undocumented relationships between the aggregate
counts/rate are assumed.

SourceIP is preserved only for result identification. The numerical feature
order is fixed. Extra fields—including AnomalyLabel, AnomalyStatus, AnomalyScore,
RiskScore and RiskLevel—are ignored even if provided. Repeated IPs are preserved
as separate input records; callers should use TASK-002 to review duplicate keys.
The expected baseline size is 30; training warns when it differs and requires
at least two rows. Inference accepts one or more rows.

## Model and preprocessing

Isolation Forest builds random trees that tend to isolate unusual records in
fewer splits. The initial model uses 100 trees, `random_state=42`, `n_jobs=1`, and
`contamination=0.1`. Contamination is configurable in (0, 0.5]; 0.1 is a teaching
starting point, not a measured attack prevalence or an optimized parameter.
It must not be tuned merely to reproduce previous predictions.

A persisted Scikit-learn Pipeline contains a ColumnTransformer selecting exactly
the five features and the IsolationForest estimator. No scaling is applied:
the tree-based model does not require it. No scaler/imputer is fit globally or
on inference data. The selector and forest are fitted only on training records;
prediction uses the persisted pipeline without fitting. The same strict input
validation and fixed column order apply at both stages.

## Outputs and score convention

Each prediction contains exactly:

- SourceIP: original identifier, preserved in input row order.
- AnomalyLabel: -1 for anomaly, 1 for normal, from `IsolationForest.predict`.
- AnomalyStatus: `Anomaly` or `Normal`, mapped from that label.
- AnomalyScore: `Pipeline.decision_function`, not `score_samples`.

Scikit-learn defines `decision_function(X) = score_samples(X) - offset_`.
Lower scores are more anomalous. Scores **below zero** are Anomaly; scores
**at or above zero** are Normal. The fitted offset depends on the training data
and contamination. Scores are not probabilities, attack confidence, or comparable
risk levels across independently trained models. Ties may prevent an exact
10% anomaly count. No RiskScore or RiskLevel is generated in TASK-003.

Commands print JSON counts of records, Normal, and Anomaly without printing IPs
or individual rows. Prediction exports contain IPs and are sensitive local data.
The previously recorded local prediction counts are observations; rerun counts
depend on the actual approved artifact/input and must not be hardcoded.

## Exact Kali Linux commands

Use reviewed main and the existing virtual environment. This section documents
the historical TASK-003 API, including its original training example; it is not
an instruction to retrain the accepted demonstration model. For current operation,
use the [final demonstration workflow](final-demonstration.md).

```bash
source .venv/bin/activate
python -m pytest -q
```

Keep your original CSV privately at, for example,
`$HOME/siem-private/ssh/ssh_baseline_features.csv`. The following is the
**historical training API reference only**, with example paths. A separately
authorized reproducibility experiment may train a distinct artifact; do not
run it to replace the existing demonstration model or bypass a version error:

```bash
python -m mini_siem.ml train \
  --input "$HOME/siem-private/ssh/ssh_baseline_features.csv" \
  --model models/ssh-isolation-v1.joblib \
  --contamination 0.1 \
  --random-state 42 \
  --output reports/ssh-training-predictions.csv
```

Reload that local model and predict without training:

```bash
python -m mini_siem.ml predict \
  --input "$HOME/siem-private/ssh/ssh_baseline_features.csv" \
  --model models/ssh-isolation-v1.joblib \
  --trust-model \
  --output reports/ssh-reloaded-predictions.json
```

Do not substitute newly extracted historical/native records. The generic API
checks numeric/schema validity, not historical provenance. Current demonstration
inference is limited to the confirmed original training baseline; any broader
reuse needs independently demonstrated semantic/window compatibility.
Change `--output` to a fresh path ending in `.csv` or `.json` to select format.
The training `--output` option is optional; counts are printed regardless.
Parent directories are created automatically. CLI outputs must not already
exist, and resolved input/output collisions are rejected. To rerun, choose a
new artifact/export name or manually remove only your known generated outputs.
Exit code 0 means success; 2 means invalid inputs/configuration, persistence, or
output errors. CLI errors do not echo source record values.

## Persistence and Python API

Joblib is explicitly declared in requirements.txt. The artifact stores the
pipeline, feature schema version and Scikit-learn version. Reload rejects
unsupported artifact schemas or different Scikit-learn versions. Restore the
trusted original matching environment; do not recreate or retrain the model
just to make the demonstration run. Dependency ranges are not an exact lockfile.
Reproducibility is tested for the same seed, data order, and installed versions;
identical results across dependency upgrades are not promised.

**Joblib uses pickle and can execute code while loading. Never load an untrusted
artifact.** Metadata validation happens after loading and is not a sandbox.
Only use `--trust-model` for an artifact you created and control; do not use it
for arbitrary downloads. The Python API likewise requires explicit trust:

```python
from mini_siem.ml.features import load_features
from mini_siem.ml.model import train_model, save_model, load_model, predict_records

records = load_features("/path/to/ssh_baseline_features.csv")
model = train_model(records, contamination=0.1, random_state=42)
save_model(model, "models/local-demo.joblib")
restored = load_model("models/local-demo.joblib", trusted=True)
results = predict_records(restored, records)
```

API callers must protect their own output paths; the CLI additionally refuses
to overwrite existing artifacts/exports. Models, CSVs, local data, and reports
are ignored by Git. JSON exports should be kept under ignored `reports/`.
Do not force-add datasets, model artifacts, or prediction exports.

## Evaluation limitations

Thirty aggregated records are too few for claims about generalization or a
stable alert threshold. Contaminated or unrepresentative baselines, feature
aggregation choices, repeated records, and seed/parameter changes can affect
results. Fitting and predicting on the same baseline is an in-sample functional
demonstration, not independent validation. A held-out dataset and independently
verified labels would be needed for meaningful supervised performance metrics.

Existing prediction files are unverified model outputs. No accuracy, precision,
recall, or F1 is calculated against them. Agreement with previous predictions
would only measure agreement; this task does not perform that optional comparison.
Synthetic tests establish software behavior, not real intrusion detection quality.
TASK-003 itself added no dashboard, monitoring loop or alert management. Later
merged tasks supply the dashboard and stored anomaly alerts; live monitoring
is still outside scope.

## Implementation validation

On Python 3.12 in the cloud, the full suite completed with **93 passed**:
44 existing tests and 49 model/CLI tests. Dependency and Git whitespace checks
passed. A separate CLI demonstration on 30 synthetic records produced **27 Normal
and 3 Anomaly** records before and after reloading. CSV and JSON results agreed,
and the source file hash was unchanged. Temporary demonstration artifacts were
removed. These counts describe only that synthetic fixture, not the real baseline.
