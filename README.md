# AI-Powered Mini SIEM

AI-Powered Mini SIEM for Real-Time Security Anomaly Detection and Alerting is a
university graduation project targeting a lightweight, local security workflow
on Kali Linux in a virtual machine.

The planned stack is Python 3, Pandas for preprocessing, Scikit-learn Isolation
Forest for anomaly detection, SQLite for storage, Streamlit for the dashboard,
and Plotly for visualization. Pytest provides automated tests and Git tracks
project changes. SQLite is included in Python's standard library.

## Current scope: TASK-001

This repository currently provides the project skeleton and import/structure
smoke tests only. Ingestion, preprocessing, anomaly detection, alert management,
storage operations, and the dashboard are not implemented. No dataset schema or
sample datasets are included. Wazuh is not used.

## Project structure

```text
ai-mini-siem/
├── .gitignore
├── README.md
├── requirements.txt
├── mini_siem/
│   ├── __init__.py
│   ├── ingestion/
│   │   └── __init__.py
│   ├── preprocessing/
│   │   └── __init__.py
│   ├── ml/
│   │   └── __init__.py
│   ├── alerts/
│   │   └── __init__.py
│   ├── storage/
│   │   └── __init__.py
│   └── dashboard/
│       └── __init__.py
└── tests/
    └── test_smoke.py
```

Each component is an importable package reserved for its corresponding future
task. There are no running services or application entry points yet.

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
# Before this task is merged, select its review branch:
git switch task-001-project-setup
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
SQLite imports, and essential project files. These checks validate initialization,
not detection accuracy or application behavior. There is no dashboard or SIEM
run command in TASK-001; application entry points will be added in later tasks.

Virtual environments, local SQLite databases, model artifacts, secrets, and
temporary files are excluded from Git. Never commit credentials or real security
logs. Use `deactivate` to leave the virtual environment.
