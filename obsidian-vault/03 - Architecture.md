---
title: "Architecture"
type: architecture
project: AI-Powered Mini SIEM
tags: [architecture]
---

# Architecture

```mermaid
flowchart LR
  H[Historical SSH CSV] --> E[SQLite events]
  B[Confirmed baseline] --> M[Trusted Isolation Forest]
  M --> P[Predictions]
  P --> A[Alerts]
  P --> D[SQLite]
  A --> D
  E --> UI[Streamlit]
  D --> UI
  L[Loopback SSH lab] --> C[Private capture]
  C --> R[Evidence review]
  R --> S[Sanitized report]
  S --> UI
```

The model inputs are EventCount, UniqueEventTypes, FailedAuthCount, InvalidUserCount, FailedAuthRate. SourceIP is an identifier only. Native lab evidence is not compatible inference input. See [[07 - Data Catalog]].
