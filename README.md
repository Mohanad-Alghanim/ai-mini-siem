# AI-Powered Mini SIEM

AI-Powered Mini SIEM for Real-Time Security Anomaly Detection and Alerting is a
university graduation project targeting a lightweight, local security workflow
on Kali Linux in a virtual machine.

The planned stack is Python 3, Pandas for preprocessing, Scikit-learn Isolation
Forest for anomaly detection, SQLite for storage, Streamlit for the dashboard,
and Plotly for visualization. Pytest provides automated tests and Git tracks
project changes. SQLite is included in Python's standard library.

## Current scope: TASK-001 through TASK-011

This repository provides the modular project skeleton, a read-only CSV inspection
and validation pipeline, an initial Isolation Forest anomaly engine, SQLite
prediction storage, anomaly alert generation, a read-only Streamlit dashboard,
and synthetic automated tests. Live monitoring is not implemented. Real-data
backend, model, and dashboard validation remain pending in the cloud. No real datasets are included.
Wazuh is not used.

The opt-in [Kali-native SSH laboratory](docs/kali-native-ssh-lab.md) uses an
independent loopback-only OpenSSH process, disposable accounts and bounded
scenarios. It collects private telemetry/inventory drafts without model or
SQLite integration. Live Kali execution and security validation remain pending.

## Project structure

```text
ai-mini-siem/
├── .gitignore
├── README.md
├── requirements.txt
├── pytest.ini
├── .streamlit/
│   └── config.toml
├── config/
│   ├── dataset_schema.example.json
│   ├── ssh_feature_contract.json
│   └── dataset_inventory.schema.json
├── docs/
│   ├── dataset-analysis.md
│   ├── ssh-anomaly-model.md
│   ├── siem-backend.md
│   ├── dashboard.md
│   ├── ssh-log-ingestion.md
│   ├── feature-compatibility.md
│   ├── feature-provenance-audit.md
│   ├── feature-pipeline-strategy.md
│   ├── feature-contract-cli.md
│   ├── dataset-inventory.md
│   ├── dataset-evaluation.md
│   └── kali-native-ssh-lab.md
├── mini_siem/
│   ├── __init__.py
│   ├── analysis.py
│   ├── backend.py
│   ├── ssh_logs.py
│   ├── feature_compatibility.py
│   ├── feature_contract.py
│   ├── datasets.py
│   ├── evaluation/
│   │   ├── __init__.py
│   │   ├── inventory.py
│   │   └── splits.py
│   ├── ingestion/
│   │   ├── __init__.py
│   │   ├── csv_loader.py
│   │   ├── ssh_backend.py
│   │   └── ssh_events.py
│   ├── preprocessing/
│   │   ├── __init__.py
│   │   ├── validation.py
│   │   ├── relationships.py
│   │   ├── ssh_features.py
│   │   └── compatibility.py
│   ├── ml/
│   │   ├── __init__.py
│   │   ├── __main__.py
│   │   ├── features.py
│   │   └── model.py
│   ├── alerts/
│   │   ├── __init__.py
│   │   └── management.py
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── sqlite.py
│   │   └── ssh_events.py
│   └── dashboard/
│       ├── __init__.py
│       ├── app.py
│       ├── charts.py
│       └── queries.py
└── tests/
    ├── test_smoke.py
    ├── test_dataset_analysis.py
    ├── test_ssh_model.py
    ├── test_backend.py
    ├── test_dashboard.py
    ├── test_ssh_logs.py
    ├── test_feature_compatibility.py
    ├── test_feature_contract.py
    └── test_dataset_evaluation.py
```

Each component is an importable package. Analysis, model, and backend CLIs are
available. The Streamlit dashboard is launched separately as described below.

## Kali Linux installation

Use Python 3.10 or newer (validated with Python 3.12). Run the following in a
terminal inside your Kali Linux VM. If Python, pip, or venv support is missing,
install the prerequisites using Kali's package manager:

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip git
```

Clone the repository, or enter your existing checkout, then create an isolated
virtual environment. Do not install Python dependencies into Kali's system
Python.

```bash
git clone https://github.com/Mohanad-Alghanim/ai-mini-siem.git
cd ai-mini-siem
# Before TASK-009 is merged, select its review branch:
git switch task-009-dataset-evaluation
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

The dependency file uses supported version ranges rather than an exact lockfile;
resolutions may differ between installation dates and Python versions. Internet
access is needed for cloning and downloading dependencies. No API keys or
external services are required for this initialization task.

## Run the available checks

Run commands from the repository root with the virtual environment activated:

```bash
python -m pytest -q
python -c "import mini_siem; import mini_siem.ingestion, mini_siem.preprocessing, mini_siem.ml, mini_siem.alerts, mini_siem.storage, mini_siem.dashboard"
```

The smoke suite checks all six component imports, required third-party and
SQLite imports, and essential project files. Dataset and model tests exercise
inspection and prediction with synthetic records. These checks do not validate
real-world detection accuracy.
Backend and dashboard commands are documented below. Live monitoring is outside the current scope.

Virtual environments, local SQLite databases, model artifacts, secrets, and
temporary files are excluded from Git. Never commit credentials or real security
logs. Use `deactivate` to leave the virtual environment.

## SSH dataset inspection (TASK-002)

The reusable read-only CSV pipeline now supports schema validation, aggregate
quality findings, authentication indicators, IP relationships, and explicitly
configured prediction/risk consistency checks. Real-data validation remains
pending; dataset tests use synthetic fixtures only. TASK-003 separately adds the
initial model described below; TASK-005 adds the read-only dashboard.

See [dataset analysis instructions](docs/dataset-analysis.md) for exact Kali Linux
commands, configurable paths, schema/policy configuration, exit codes, and data
quality limitations. Start with:

```bash
python -m mini_siem.analysis --data-dir "$HOME/siem-private/ssh" --output-dir reports/ssh
```

## Initial SSH anomaly model (TASK-003)

The educational Isolation Forest engine trains on exactly five validated
behavioral features, preserves SourceIP only for identification, and supports
trusted local model persistence and CSV/JSON prediction exports. See
[model instructions](docs/ssh-anomaly-model.md) for exact Kali commands, scoring
conventions, safety requirements for joblib, and evaluation limitations.

```bash
python -m mini_siem.ml --help
```

Real-data model validation remains pending in the cloud. Existing predictions
are not ground truth; unusual behavior is not proof of an attack.

## SQLite backend and AI alerts (TASK-004)

The backend stores feature ingestion batches and AI predictions transactionally,
creates alerts only for anomalies, and preserves history on duplicate retries.
It uses an existing trusted model without retraining. See
[backend instructions](docs/siem-backend.md) for schema, batch/model identities,
UTC timestamp semantics, exact Kali commands, and limitations.

```bash
python -m mini_siem.backend --help
```


## Streamlit dashboard (TASK-005)

The local dashboard reads the existing database without writes, showing global
KPIs and Plotly charts plus filterable alert/prediction tables. It does not
retrain models or generate demo data. See [dashboard instructions](docs/dashboard.md)
for launch commands, refresh semantics, read-only safeguards, and limitations.

```bash
MINI_SIEM_DATABASE="$PWD/data/mini-siem.db" \
  python -m streamlit run mini_siem/dashboard/app.py \
  --server.address 127.0.0.1 --browser.gatherUsageStats false
```

Use locally only; public exposure requires authentication and additional security.


## Historical SSH events and feature review (TASK-006)

Parse the structured historical CSV, export observed IP-level features, compare
an optional baseline, and persist every validated event including rows without
IPs. Generated features are **not automatically sent to the model**; compatibility
requires independent semantic review. Raw-content preservation uses an explicit,
optional additive storage extension. See [SSH ingestion instructions](docs/ssh-log-ingestion.md)
for formulas, parser scope, storage proposal, privacy rules, and Kali commands.

```bash
python -m mini_siem.ssh_logs --help
```


## Feature compatibility investigation (TASK-007)

A read-only diagnostic traces per-IP feature differences to event references,
separates confirmed observations from hypotheses, and keeps model inference
blocked while original baseline semantics remain unverified. It changes no
parser, feature definition, model or database behavior. See
[compatibility investigation](docs/feature-compatibility.md) for Kali commands,
report interpretation, scientific limitations and safe future strategies.

```bash
python -m mini_siem.feature_compatibility --help
```


## Feature contract and future model strategy (TASK-008)

The [provenance audit](docs/feature-provenance-audit.md) identifies missing legacy
baseline-generation evidence. The [versioned contract](config/ssh_feature_contract.json)
records existing feature rules without changing them. The
[strategy and consistency design](docs/feature-pipeline-strategy.md) recommends a
separately reviewed reproducible experimental pipeline if legacy compatibility
cannot be established; it does not authorize training. The
[read-only CLI](docs/feature-contract-cli.md) checks contract/runtime drift and can
inspect local input hashes. A valid contract never enables inference or training.

```bash
python -m mini_siem.feature_contract
```


## Dataset inventory and evaluation planning (TASK-009)

The [inventory guide](docs/dataset-inventory.md) documents private metadata
registration, read-only quality checks and current SSH vs future source categories.
The [evaluation methodology](docs/dataset-evaluation.md) covers conservative
independent-group splits, trusted temporal requirements, and separate unlabeled
and independently labeled evaluation. Plans do not train models, execute attacks,
change SQLite, or authorize inference.

```bash
python -m mini_siem.datasets --help
```

Native lab code: `mini_siem/native_lab/{control,safety,telemetry}.py`; CLI:
`python -m mini_siem.kali_ssh_lab --help`; synthetic tests:
`tests/test_kali_ssh_lab.py`. Follow the [Kali guide](docs/kali-native-ssh-lab.md)
for explicit privileged lifecycle commands and unchanged-system-service checks.

TASK-011 adds a [read-only SSH evidence review](docs/ssh-evidence-review.md)
with privacy-safe reports and explicitly unresolved experiment correlation.
Run `python -m mini_siem.evidence_review --help` for the CLI. Default pytest
discovery is limited to `tests/` by the repository-level `pytest.ini`.
