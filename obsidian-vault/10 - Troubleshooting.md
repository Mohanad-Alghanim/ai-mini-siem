---
title: "Troubleshooting"
type: runbook
project: AI-Powered Mini SIEM
tags: [troubleshooting]
---

# Troubleshooting

| Symptom | Safe check |
|---|---|
| `sklearn` or `streamlit` missing | Use `.venv/bin/python` or activate project venv |
| Database missing | Verify local `data/mini-siem.db`; not distributed on GitHub |
| Port 8501 busy | Inspect `ss -ltnp 'sport = :8501'`; stop only your own session |
| Protected capture unreadable | Intentional root-only controls; authorized sanitized report handoff |
| Python model/runtime mismatch | Use matching trusted runtime; do not retrain to silence errors |
| Git seems unchanged | Confirm PR merged, then `git pull --ff-only origin main` |

Avoid broad permission changes, force cleaning Git, and killing unrelated SSH processes.
