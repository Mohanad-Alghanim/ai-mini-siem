---
title: "Project Overview"
type: overview
project: AI-Powered Mini SIEM
tags: [overview]
---

# Project Overview

The Mini SIEM is a local Kali Linux university proof of concept for **offline** SSH anomaly analysis. Historical events are saved in SQLite and displayed alongside stored Isolation Forest predictions and anomaly alerts in Streamlit.

Previous Kali observations: 2,000 historical SSH events; 30 aggregate predictions (27 Normal, 3 Anomaly), 3 alerts. These are historical observations, not guaranteed values in a fresh installation.

The restricted local OpenSSH laboratory produces **separate** evidence; its events are not submitted to the legacy model.

Related: [[03 - Architecture]], [[09 - Limitations]].
