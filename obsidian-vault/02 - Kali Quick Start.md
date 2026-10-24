---
title: "Kali Quick Start"
type: runbook
project: AI-Powered Mini SIEM
tags: [kali, runbook]
---

# Kali Quick Start

For the **existing prepared Kali machine**:

```bash
cd ~/ai-mini-siem
source .venv/bin/activate
export MINI_SIEM_DATABASE="$PWD/data/mini-siem.db"
python -m streamlit run mini_siem/dashboard/app.py \
  --server.address 127.0.0.1 \
  --server.port 8501 \
  --browser.gatherUsageStats false
```

Open http://127.0.0.1:8501 in the Kali browser. Stop with **Ctrl+C**. Rerun the same commands tomorrow.

An approved V2 report, if already available to the dashboard user:
```bash
export MINI_SIEM_LAB_REVIEW="$PWD/reports/dashboard-evidence/review.json"
```

For a **fresh Kali clone**:
```bash
cd ~
git clone --branch main https://github.com/Mohanad-Alghanim/ai-mini-siem.git
cd ai-mini-siem
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

The populated SQLite database and private inputs are **not in GitHub**. An empty DB may be created explicitly with `python -m mini_siem.backend init --database data/mini-siem.db`. This will not create real demonstration data.
