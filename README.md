# CyberShelter UAE Internship — Detection Engineering Repository

**Intern:** Mohammed Farhan
**Role:** Associate — Information Security (Intern)
**Program:** Security Engineering / Detection Engineering Internship

---

## Overview

This repository contains the detection engineering deliverables produced during the internship, organized by week and by day. Week 2 (Days 8–14) covers ATT&CK-based coverage mapping, custom Sigma and Wazuh rule development, Sigma format conversion, adversary emulation testing, alert tuning, and threat hunting.

---

## Repository Structure

```
week-2/                          Week 1 deliverables (Linux hardening, SIEM deployment, Splunk, ELK)
week-3/                          Week 2 deliverables (detection engineering — see below)
  ├── day-8-deliverables/        ATT&CK coverage gap analysis
  ├── day-9-deliverables/        Custom Sigma rules
  ├── day-10-deliverables/       Sigma format conversion + Wazuh deployment
  ├── day-11-deliverable.pdf     Adversary emulation (Atomic Red Team)
  ├── day-12-deliverables/       Custom Wazuh rules + alert tuning
  ├── day-13-deliverables/       Threat hunting
  └── day-14-deliverables/       Consolidation + final validation
```

---

## Week 2 — Day-by-Day Summary

### Day 8 — ATT&CK Coverage Gap Analysis
Mapped existing detection coverage against MITRE ATT&CK using Navigator, classifying techniques as covered (Green), partially covered — log source exists but no detection (Blue), or uncovered (Red).
**Contents:** `day-8-coverage-map-layer.json`, `day-8-report.pdf`

### Day 9 — Custom Sigma Rules
Wrote 3 original Sigma detection rules from scratch: Windows Defender disabled, encoded PowerShell command execution, and new administrator account creation.
**Contents:** `rule1-defender-disabled.yml`, `rule2-powershell-encoded.yml`, `rule3-new-admin-account.yml`, `day-9-report.pdf`

### Day 10 — Sigma Conversion and Wazuh Deployment
Converted the Day 9 rules to Splunk SPL, Elastic Lucene, and QRadar AQL using sigma-cli. Separately, sourced 5 rules from the SigmaHQ community repository, converted them to Wazuh XML (via SigWaz, since neither sigma-cli nor Uncoder.IO supports Wazuh as a target), and deployed them into the Wazuh ruleset.
**Contents:** 5 community Sigma YAML files, 5 converted Wazuh XML files, `day-10-report.pdf`

### Day 11 — Adversary Emulation
Ran 5 Atomic Red Team tests mapped to distinct ATT&CK techniques against the Windows lab VM, checking whether Wazuh alerted on each and whether tagging was accurate. Identified a genuine mistagging bug in a built-in Wazuh rule.
**Contents:** `day-11-deliverable.pdf`

### Day 12 — Custom Wazuh Rules + Alert Tuning
Wrote 3 custom Wazuh XML rules (privileged file staging in /tmp, SSH brute-force composite, netcat reverse shell detection) and performed a full alert-tuning exercise on a noisy built-in rule, with documented before/after volume and business justification for the exclusion.
**Contents:** 4 Wazuh XML rules (3 detections + 1 tuning exception), tuning report, `day-12-report.pdf`

### Day 13 — Threat Hunting
Ran a hypothesis-driven threat hunt (PowerShell-based lateral movement) using Wazuh Discover, including discovering and enabling a missing log source (PowerShell Script Block Logging). Also ran Hayabusa against exported Windows event logs and triaged all resulting high-severity detections.
**Contents:** Activity summary report, threat hunt report

### Day 14 — Consolidation + Final Validation
Updated the Day 8 ATT&CK Navigator layer with all detections built during Week 2, and ran one final end-to-end Atomic Red Team validation (emulate → detect → alert → triage → document) to confirm the full detection pipeline remains reliable.
**Contents:** Updated ATT&CK Navigator layer JSON, `day-14-report.pdf`

---

## Summary of Detections Built

| Rule Type | Count |
|---|---|
| Sigma rules (self-written) | 3 |
| Sigma rules (SigmaHQ community, deployed) | 5 |
| Custom Wazuh rules | 3 |
| Wazuh tuning/exception rules | 1 |

## MITRE ATT&CK Coverage Added in Week 2

T1562.001 (Defense Impairment), T1059.004 (Execution), T1547.001 (Persistence), T1074 (Collection), T1070 (Defense Evasion), T1021.006 (Lateral Movement — gap identified, detection recommended).

---

## Notes

Several genuine technical limitations were encountered and documented honestly rather than concealed, including an unresolved Wazuh custom composite-rule firing issue (Day 12) and a scope-limited threat hunt conclusion (Day 13). These are recorded in full in their respective day folders as part of standard detection engineering practice.
