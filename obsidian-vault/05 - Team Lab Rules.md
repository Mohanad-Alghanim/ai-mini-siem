---
title: "Team Lab Rules"
type: policy
project: AI-Powered Mini SIEM
tags: [lab, security]
---

# Team Lab Rules

The optional OpenSSH laboratory binds **only 127.0.0.1:2222 on the Kali host**. It cannot be accessed directly from teammates' separate machines. Do not widen it to 0.0.0.0 or use tunnels.

Permitted fixed scenarios: `success`, `single-failure`, `three-failures`, and `session-logout`. They use disposable keys and a restricted account, not arbitrary passwords, targets or shells. A trained operator handles prepare/start/verify/stop/collect/cleanup with system service checks. Review [native lab instructions](https://github.com/Mohanad-Alghanim/ai-mini-siem/blob/main/docs/kali-native-ssh-lab.md) before privileged action.

Never upload private logs, keys or database dumps. Coordinate authorized tests and share only approved sanitized reports. See [[06 - Six Attack Scope]].
