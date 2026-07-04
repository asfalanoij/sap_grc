# SAP GRC-Lite — Compliance-as-Code for SAP User Access Management

**SAP S/4HANA Client 300 | Company X | Ruleset v2.0 | Proof of Concept**

**ICoFR Basis:** Internal Regulation No. 11/2024 (COSO 2013) | Audit: PCAOB AS 2201 / AS 1105

---

## Problem Statement

Company X runs its core financial processes on SAP S/4HANA. Who can do what
inside SAP is therefore a direct driver of financial-reporting risk: a single
user who can both create a vendor and approve a payment to that vendor can
commit and conceal fraud without any second pair of eyes.

Today, the controls that manage this risk have four structural weaknesses:

1. **User Access Reviews are manual and periodic.** Role assignments are
   exported to spreadsheets once a quarter, circulated by email, and reviewed
   by people who cannot realistically evaluate thousands of user-role rows.
   Between review cycles — up to 90 days — violations accumulate undetected.

2. **Segregation-of-Duties (SoD) conflicts are found late, by the auditor.**
   Internal Audit and external audit detect conflicts *after* they have
   existed for months. Detection at audit time means the ICoFR deficiency has
   already occurred; the finding documents the failure rather than preventing it.

3. **The same findings recur cycle after cycle.** Access is revoked to close
   the finding, then re-granted weeks later because the underlying role design
   or joiner-mover-leaver process was never fixed. Nothing in the current
   process *measures* recurrence, so root causes stay invisible to management.

4. **Evidence is fragile.** Review evidence lives in spreadsheets and email
   threads. It is hard to prove *when* a check ran, *what* data it ran
   against, and that the results were not edited afterwards — exactly the
   questions PCAOB AS 1105 asks about evidence reliability.

The commercial answer — SAP GRC Access Control — addresses this, but at a
license and implementation cost that is difficult to justify for a single
S/4HANA client. **This PoC tests a third way: express the access-control
ruleset as version-controlled code, run it automatically, and let the pipeline
produce its own audit evidence.** If the concept proves out, the business case
for (or against) a full GRC platform can be made with data instead of opinion.

## The Approach: Compliance-as-Code

Three ideas, borrowed from software engineering and applied to internal control:

| Idea | In software | In this PoC |
|------|-------------|-------------|
| Single source of truth | Code in git, reviewed via pull request | SoD matrix, privileged-access and dormancy rules in YAML — every change reviewed, versioned, attributable |
| Continuous integration | Tests run on every change | Rules engine runs daily and on every ruleset change via GitHub Actions |
| Immutable artifacts | Build outputs are hashed and archived | Findings are timestamped, hashed, and committed per cycle |

The intended data flow:

```
SAP S/4HANA (SUIM / USR02 / AGR_USERS export)
        │
        ▼
data/user_roles.json          ← user-role snapshot per cycle
        │
        ▼
checks/run_checks.py          ← evaluates rules/*.yaml
        │
        ├── SoD conflicts          (rules/sod_matrix.yaml)
        ├── Privileged access      (rules/privileged_access.yaml)
        └── Dormant accounts       (rules/dormant_accounts.yaml)
        │
        ▼
evidence/findings_<cycle>.json ← hashed findings, severity-scored
        │
        ├── CI gate: CRITICAL finding → pipeline fails → immediate attention
        └── Recurrence tracking → repeated findings escalate to root-cause review
```

## Governance (Three Lines Model)

| Line | Role | Responsibility here |
|------|------|---------------------|
| 1st — IT | Owner of **operation** | Runs the pipeline, remediates findings within SLA |
| 2nd — GR Unit + IT Risk | Owner of **definition** | Owns the ruleset and control register; approves rule changes |
| 3rd — Internal Audit | **Assurance** | Independent evaluation of design and operating effectiveness; author of this PoC as advisory work for the IT division |

## Control Register

| Control ID | Name | Type | Frequency | Owner |
|-----------|------|------|-----------|-------|
| KC-01 | SoD Matrix Review | Preventive | Quarterly | IT Risk |
| KC-02 | Privileged Access Recertification | Preventive | Quarterly | IT |
| KC-03 | SoD Violation Detection | Detective | Daily | IT |
| KC-04 | Dormant Account Detection | Detective | Monthly | IT |
| KC-05 | Access Recurrence Flagging | Detective | Per cycle | Internal Audit |
| KC-06 | Evidence Archival | Corrective | Per cycle | IT Risk |

The differentiating design element is the **feedback loop**: detective
controls (KC-03..KC-05) do not just raise findings — recurrence of the same
finding across cycles is classified (NONE → RECURRING → CHRONIC → SYSTEMIC)
and chronic findings trigger the preventive controls (KC-01/KC-02) to revisit
role design, closing the loop that manual UAR never closes.

## Repository Structure

```
sap_grc/
├── .github/workflows/grc_checks.yml   # CI pipeline: scheduled + on-change runs
├── checks/run_checks.py               # Rules engine (Python 3, pyyaml)
├── rules/
│   ├── sod_matrix.yaml                # SoD conflict pairs (5 conflicts)
│   ├── privileged_access.yaml         # Privileged profile allowlists (SAP_ALL etc.)
│   └── dormant_accounts.yaml          # Inactivity thresholds by account type
├── controls/control_register.yaml     # KC-01..KC-06, COSO-mapped
├── remediation/remediation.yaml       # SLA, escalation, recurrence policy
├── evidence/sample_findings.json      # Illustrative findings output
├── slides.md                          # Executive brief (Marp)
└── README.md
```

## Quick Start

```bash
git clone https://github.com/asfalanoij/sap_grc.git
cd sap_grc

# The engine needs a user-role snapshot. Place your export at
# data/user_roles.json — a JSON array of user records:
#
#   [
#     {
#       "user_id": "JDOE",
#       "roles": ["Z_AP_INVOICE_ENTRY", "Z_AP_PAYMENT_RUN"],
#       "profiles": [],
#       "account_type": "standard",
#       "account_status": "ACTIVE",
#       "last_login_date": "2026-05-14"
#     }
#   ]

python3 checks/run_checks.py --input data/user_roles.json

# Findings land in evidence/, and the process exits non-zero
# if any CRITICAL finding is detected.
```

## Current Status — Read Before Relying on This

This is a **proof of concept under active hardening**, not an operating
control. An Internal Audit diagnosis (2026-07) confirmed the ruleset design
and control taxonomy are sound, but identified gaps that are being remediated
under an approved workplan:

- **No SAP ingestion yet.** There is no automated SUIM/USR02/AGR_USERS
  extraction; the engine currently requires a manually supplied JSON export,
  and the repository ships no sample dataset.
- **Recurrence tracking (KC-05) is designed but not yet implemented** — all
  findings currently report recurrence `NONE`.
- **Evidence hashing is being reworked.** The current per-run hash is not yet
  a reliable tamper-evidence mechanism; do not cite it as such in audit
  workpapers until the hardened evidence chain lands.
- **Known engine defects** (dormancy thresholds for service/emergency
  accounts, error handling on malformed input) are queued for fix, alongside
  a test suite and `requirements.txt`.

Treat current outputs as illustrative. The PoC's purpose is to prove the
*concept* to management; production adoption requires the workplan to complete
plus a formal control-design sign-off by the 2nd line.

## Ruleset Versioning

Semantic versioning (`MAJOR.MINOR.PATCH`): **MAJOR** = control-framework
structure changes, **MINOR** = new rules/controls, **PATCH** = threshold or
label corrections. Current: `v2.0.0`.

## License

Internal use only. Not for public distribution.

---
*GRC Blueprint | Company X | Internal Audit Division (advisory to IT) | v2.0*
