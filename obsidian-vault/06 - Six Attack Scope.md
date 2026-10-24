---
title: "Six Attack Scope"
type: status
project: AI-Powered Mini SIEM
tags: [attacks, scope]
---

# Six Attack Scope

| Planned attack | Current status |
|---|---|
| SSH brute-force indicators | Bounded 3-key-failure scenario; no validated brute-force classifier |
| Password spraying | Unsupported; no suitable multi-account evidence |
| Port scanning | Unsupported; no network-flow detector |
| SQL injection | Unsupported; no application/HTTP detector |
| File modification | Unsupported; no file integrity telemetry |
| DoS | Unsupported; no controlled request/service metric detector |

The AI operates offline on its original SSH baseline, not on live traffic. These five unsupported attacks cannot be tested **against the protected SSH lab as a substitute**. See [[09 - Limitations]].
