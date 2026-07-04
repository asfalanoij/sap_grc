# SAP GRC-Lite for Company X

**SAP S/4HANA Client 300 | Company X | Ruleset v2.0**

**ICoFR Basis:** Internal Regulation No. 11/2024 (COSO 2013) | Audit: PCAOB AS 2201 / AS 1105

---

## Overview

This repository contains the SAP GRC-Lite ruleset and compliance-as-code blueprint for Company X's SAP S/4HANA (Client 300) User Access Management (UAM) and User Access Review (UAR) program.

**Owner of DEFINITION:** GR Unit + IT Risk (2nd line)
**Owner of OPERATION:** IT (1st line)
**Assurance:** Internal Audit (3rd line)

## Standards & Frameworks

- **ICoFR Basis:** Internal Regulation No. 11/2024 (COSO 2013)
- **Audit Standard:** PCAOB AS 2201 / AS 1105
- **Review Period:** 2026-01-01 to 2026-06-30

## Repository Structure

```
sap_grc/
├── .github/
│   └── workflows/
│       └── grc_checks.yml          # CI/CD pipeline
├── checks/
│   └── run_checks.py               # Rules engine (Python)
├── rules/
│   ├── sod_matrix.yaml             # SoD conflict definitions
│   ├── privileged_access.yaml      # Privileged access rules
│   └── dormant_accounts.yaml       # Dormant/inactive account rules
├── remediation/
│   └── remediation.yaml            # Remediation tracking & SLA
├── evidence/
│   └── sample_findings.json        # SHA256-hashed findings
├── controls/
│   └── control_register.yaml       # Control register (KC-01 to KC-06)
├── slides.md                       # Executive summary (Marp)
└── README.md
```

## Control Register Summary

| Control ID | Name | Type | Frequency | Owner |
|-----------|------|------|-----------|-------|
| KC-01 | SoD Matrix Review | Preventive | Quarterly | IT Risk |
| KC-02 | Privileged Access Recertification | Preventive | Quarterly | IT |
| KC-03 | SoD Violation Detection | Detective | Daily | IT |
| KC-04 | Dormant Account Detection | Detective | Monthly | IT |
| KC-05 | Access Recurrence Flagging | Detective | Per cycle | Internal Audit |
| KC-06 | Evidence Archival | Corrective | Per cycle | IT Risk |

## Feedback Loop Architecture

The blueprint adds a **feedback loop** between detective and preventive controls:

1. **Detect** (KC-03 to KC-06) → Findings flagged with recurrence flag
2. **Track** (remediation.yaml) → SLA, escalation, root-cause required
3. **Feed back** (KC-01/KC-02) → Function matrix review triggered on repeated SoD hits
4. **Evidence** → SHA256-hashed, timestamped findings per cycle

## Tech Stack

| Layer | Tool | Purpose |
|-------|------|---------|
| Rules definition | YAML | Single source of truth, version-controlled |
| Rules engine | Python 3.x | Evaluates rules against user-role data |
| CI/CD | GitHub Actions | Daily scheduled runs + on-change triggers |
| Evidence storage | JSON + git | Hash-traceable, timestamped findings |

## How to Use

```bash
# Clone the repo
git clone https://github.com/asfalanoij/sap_grc.git
cd sap_grc

# Run the rules engine (requires user-role data in JSON format)
python checks/run_checks.py

# Check generated evidence
cat evidence/sample_findings.json
```

## Ruleset Versioning

All rulesets follow semantic versioning (`MAJOR.MINOR.PATCH`):
- **MAJOR**: Structural changes to control framework
- **MINOR**: New rules or control additions
- **PATCH**: Threshold adjustments or label corrections

Current version: `v2.0.0`

## Evidence Integrity

All findings are SHA256-hashed at generation time and committed to git. This provides:
- Immutable audit trail
- Tamper-evident evidence chain
- Cycle-over-cycle recurrence tracking

## License

Internal use only. Not for public distribution.

---
*GRC Blueprint | Company X | Internal Audit Division | v2.0*
