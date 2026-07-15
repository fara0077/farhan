# Week 1 — SIEM Foundations, Log Management & Detection Basics

**Intern:** Mohammed Farhan
**Role:** Associate — Information Security (Intern)
**Program:** Security Engineering / Detection Engineering Internship

---

## Overview

Week 1 covered the foundational infrastructure of a SOC environment — hardening a Linux server, centralizing log collection, deploying and configuring a SIEM (Wazuh), standing up Splunk and the Elastic Stack in parallel, and writing the first custom detection content from scratch. Each day built directly on the previous one, culminating in a consolidated, working multi-SIEM lab environment by Day 7.

---

## Day-by-Day Summary

### Day 1 — Linux Security Hardening + auditd
Hardened the Ubuntu Server lab host: removed telnet, enforced a stronger password policy (minimum 14 characters via `pwquality.conf`), hardened SSH configuration (`PermitRootLogin no`, `MaxAuthTries 4`), configured UFW to deny incoming traffic by default while allowing SSH and HTTPS, and installed `auditd` with the Neo23x0 community ruleset (206 rules) for system call monitoring.
**File:** `day-1-linux-hardening.pdf`

### Day 2 — Log Sources & Log Management Architecture
Established centralized log collection: configured rsyslog to forward Ubuntu Server's logs to Kali over port 514, installed Sysmon on the Windows 10 endpoint using the SwiftOnSecurity configuration template, and mapped 10 critical Windows Event IDs to their corresponding attack techniques as a reference for future detection work.
**File:** `day-2-log-architecture.pdf`

### Day 3 — Wazuh SIEM/XDR Deployment
Deployed Wazuh (single-node, v4.9.0) via Docker Compose and enrolled all three lab machines (Kali, Windows 10, Ubuntu Server) as agents. Configured the Ubuntu Server agent to monitor `/var/log/auth.log`, enabling brute-force detection — verified working by confirming Wazuh's built-in rule 5760 fired correctly, mapped to MITRE ATT&CK T1110.001.
**File:** `day-3-wazu-deployment.pdf`

### Day 4 — Wazuh Dashboards & File Integrity Monitoring
Configured File Integrity Monitoring (FIM) to watch key system directories, confirmed the vulnerability detection module was active and triaged 5 real CVE findings against the lab environment, and built a custom OpenSearch dashboard in the Wazuh interface covering top alert types, alert volume over time, and source IP activity.
**File:** `day-4-FIM-monitoring.pdf`

### Day 5 — Splunk Free: Ingestion, SPL, and Alerting
Installed Splunk Free and ingested three log sources: live Linux authentication logs, a static Windows Security Event Log export, and UFW firewall logs from Kali. Diagnosed and fixed a broken Universal Forwarder configuration (pointing to an outdated IP address), and built an 8-detection SPL search cheat sheet, each mapped to a corresponding MITRE ATT&CK technique.
**File:** `day-5-splunk.pdf`

### Day 6 — Elastic Stack Fundamentals + Filebeat
Deployed the Elastic Stack (Elasticsearch, Logstash, Kibana) via Docker and configured Filebeat with the auditd and nginx modules to ship log data into it. Resolved a YAML configuration syntax error that was silently preventing Filebeat from starting, built a 3-visualization Kibana dashboard (failed SSH attempts, top source IPs, HTTP error codes), and produced a direct comparison of SPL versus KQL syntax across 5 equivalent detection use cases.
**File:** `day-6-ELK-Stack.pdf`

### Day 7 — SIEM Log Normalisation, Parsing & Week 1 Consolidation
Wrote a custom Wazuh decoder and detection rule from scratch for a fictional application log format, working through genuine regex engine limitations (escaped brackets and digit quantifiers not supported by Wazuh's default engine) to reach a working solution. Built a two-stage composite rule pattern — a base detection plus a frequency-based escalation rule — to detect repeated failures within a time window, the same structural pattern reused throughout later weeks. Closed the week by consolidating all Week 1 deliverables into a single submission.
**File:** `day-7-SIEM-log-normalisation-and-parsing.pdf`

---

## Summary of What Was Built

| Component | Status |
|---|---|
| Hardened Linux baseline (SSH, firewall, password policy, auditd) | ✅ |
| Centralized log forwarding (rsyslog + Sysmon) | ✅ |
| Wazuh SIEM deployed, 3 agents enrolled | ✅ |
| File Integrity Monitoring + vulnerability detection | ✅ |
| Splunk deployed, 8 SPL detections mapped to ATT&CK | ✅ |
| Elastic Stack deployed, Kibana dashboard + KQL detections | ✅ |
| First custom Wazuh decoder + composite detection rule | ✅ |

---

## Notes

This week established the environment and skills that all subsequent detection engineering work (Week 2) was built on top of — the Wazuh deployment, agent configuration, and the base/escalation composite rule pattern from Day 7 were reused and extended repeatedly in later weeks.
