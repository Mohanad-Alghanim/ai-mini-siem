---
title: "Data Catalog"
type: index
project: AI-Powered Mini SIEM
tags: [data, catalog]
---

# Data Catalog

| Dataset/evidence | Observed scope | Scientific caveat |
|---|---|---|
| Structured SSH events | 2,000 rows, 1,647 with observed IP attribution | 353 lack supported source attribution |
| Legacy baseline | 30 per-IP feature rows | Provenance and compatibility incomplete |
| Predictions/alerts | 27 Normal, 3 Anomaly, 3 Alerts | In-sample and unverified ground truth |
| Native SSH lab | 39 records, 31 initially supported, 8 unsupported | 23 with source; experiment labels unresolved |

These are **previous local observations** rather than files packaged with the repository. Files such as `data/mini-siem.db`, raw `capture-001`, key files and private CSVs remain private. Newly computed SSH features differ for 22 of 30 IPs vs the legacy baseline, so do not force them into the old model.

See [[09 - Limitations]] and [[12 - Sources]].
