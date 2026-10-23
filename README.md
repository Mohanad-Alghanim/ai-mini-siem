# AI-Powered Mini SIEM

AI-Powered Mini SIEM for Real-Time Security Anomaly Detection and Alerting is a
university graduation project targeting a lightweight, local security workflow
on Kali Linux in a virtual machine.

The planned stack is Python 3, Pandas for preprocessing, Scikit-learn Isolation
Forest for anomaly detection, SQLite for storage, Streamlit for the dashboard,
and Plotly for visualization. Pytest provides automated tests and Git tracks
project changes. SQLite is included in Python's standard library.

## Current scope: TASK-001 through TASK-003

This repository provides the modular project skeleton, a read-only CSV inspection
and validation pipeline, an initial Isolation Forest anomaly engine, and automated
tests using synthetic fixtures. Alert management, storage operations, and the
dashboard are not implemented. Real-data model validation remains pending in the
cloud. No real datasets are included. Wazuh is not used.

## Project structure

```text
ai-mini-siem/
├── .gitignore
├── README.md
├── requirements.txt
├── config/
│   └── dataset_schema.example.json
├── docs/
│   ├── dataset-analysis.md
│   └── ssh-anomaly-model.md
├── mini_siem/
│   ├── __init__.py
│   ├── analysis.py
│   ├── ingestion/
│   │   ├── __init__.py
│   │   └── csv_loader.py
│   ├── preprocessing/
│   │   ├── __init__.py
│   │   ├── validation.py
│   │   └── relationships.py
│   ├── ml/
│   │   ├── __init__.py
│   │   ├── __main__.py
│   │   ├── features.py
│   │   └── model.py
│   ├── alerts/
│   │   └── __init__.py
│   ├── storage/
│   │   └── __init__.py
│   └── dashboard/
│       └── __init__.py
└── tests/
    ├── test_smoke.py
    ├── test_dataset_analysis.py
    └── test_ssh_model.py
```

Each component is an importable package. CSV analysis and model CLIs are available;
there are no running services or SIEM/dashboard entry points yet.

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
# Before TASK-003 is merged, select its review branch:
git switch task-003-ssh-anomaly-model
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
There is no dashboard or SIEM run command; those entry points belong to later tasks.

Virtual environments, local SQLite databases, model artifacts, secrets, and
temporary files are excluded from Git. Never commit credentials or real security
logs. Use `deactivate` to leave the virtual environment.

## SSH dataset inspection (TASK-002)

The reusable read-only CSV pipeline now supports schema validation, aggregate
quality findings, authentication indicators, IP relationships, and explicitly
configured prediction/risk consistency checks. Real-data validation remains
pending; dataset tests use synthetic fixtures only. TASK-003 separately adds the
initial model described below. No dashboard has been added.

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
