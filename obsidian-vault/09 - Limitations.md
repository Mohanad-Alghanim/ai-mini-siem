---
title: "Limitations"
type: research
project: AI-Powered Mini SIEM
tags: [limitations]
---

# Limitations

- Offline model, not real-time AI monitoring.
- Only the trusted original 30-row baseline is compatible with the legacy Isolation Forest.
- Baseline provenance is incomplete; newly derived features showed differences for 22/30 IPs.
- No independent test labels, validated accuracy/recall or generalization.
- Native SSH event timestamps and per-experiment linkage are unresolved.
- Earlier V1 evidence classifier returned 39 ambiguous messages; V2 accommodates CRLF/fixed forced-command forms, but post-fix private counts were not provided in the available project record.
- Five non-SSH attack categories remain unsupported.

Do not call an anomaly a confirmed attack.
