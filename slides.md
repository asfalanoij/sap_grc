---
marp: true
theme: default
paginate: true
footer: 'SAP GRC-Lite | Company X | CONFIDENTIAL | v2.0 | Review Period: 2026-Q1'
---

<!-- ============================================================ -->
<!-- PAGE 1 — VP INTERNAL AUDIT                                   -->
<!-- ============================================================ -->

# SAP GRC-Lite Blueprint
### VP Internal Audit Briefing — Audit Assurance & Control Evidence

**System:** SAP S/4HANA Client 300 | **Ruleset:** v2.0.0 | **Cycle:** 2026-Q1
**Basis:** ICoFR Internal Reg. No. 11/2024 (COSO 2013) | PCAOB AS 2201 / AS 1105

---

## What Has Been Built (Audit Perspective)

| Control | ID | Type | Frequency | Audit Assertion |
|---------|-----|------|-----------|------------------|
| SoD Matrix Review | KC-01 | Preventive | Quarterly | Completeness, Existence |
| Privileged Access Recertification | KC-02 | Preventive | Quarterly | Existence, Rights |
| SoD Violation Detection | KC-03 | Detective | **Daily** | Completeness |
| Dormant Account Detection | KC-04 | Detective | Monthly | Existence |
| Recurrence Flagging | KC-05 | Detective | Per cycle | Completeness, Valuation |
| Evidence Archival | KC-06 | Corrective | Per cycle | Completeness, Existence |

**3-Line Model Alignment:**
- 1st Line: IT operates controls (KC-01 to KC-04)
- 2nd Line: IT Risk owns ruleset definition & escalation
- 3rd Line: Internal Audit assures via KC-05/KC-06 review

---

## Audit Evidence Quality

**Every finding is:**
- SHA256-hashed at generation time — tamper-evident
- Timestamped with ISO 8601 detection date
- Tagged with cycle ID (e.g. `2026-Q1`) for period mapping
- Committed to git — immutable, version-controlled audit trail
- Auto-classified: `NONE → RECURRING → CHRONIC → SYSTEMIC`

**Recurrence Policy (key for PCAOB AS 1105 / ICoFR):**

| Flag | Trigger | Required Action |
|------|---------|------------------|
| RECURRING | 2nd consecutive cycle | Root cause analysis mandatory |
| CHRONIC | 3rd cycle | Root cause + approved action plan |
| SYSTEMIC | 4th+ cycle | Management attestation + Audit Committee notification |

**SLA Structure:** CRITICAL = 3 days / HIGH = 7 days / MEDIUM = 14 days

**Internal Audit Role:** Validate recurrence flags each cycle, review root cause quality, confirm evidence integrity, sign off on KC-05/KC-06.

---

<!-- ============================================================ -->
<!-- PAGE 2 — VP IT                                               -->
<!-- ============================================================ -->

# SAP GRC-Lite Blueprint
### VP IT Briefing — System Architecture & Operational Responsibilities

**Stack:** Python 3.11 | YAML Rulesets | GitHub Actions CI/CD | JSON Evidence Store
**Repo:** `github.com/asfalanoij/sap_grc` | **Branch:** `main`

---

## Architecture & Tech Stack

```
sap_grc/
├── .github/workflows/grc_checks.yml   ← CI/CD: daily run + on-push trigger
├── rules/
│   ├── sod_matrix.yaml                ← 5 SoD conflict pairs (CRITICAL–MEDIUM)
│   ├── privileged_access.yaml         ← SAP_ALL, SAP_NEW, Firefighter ID rules
│   └── dormant_accounts.yaml          ← 90/30/60-day inactivity thresholds
├── checks/run_checks.py               ← Rules engine (Python, ~270 LOC)
├── controls/control_register.yaml     ← KC-01 to KC-06 full definitions
├── remediation/remediation.yaml       ← SLA + recurrence + lifecycle config
└── evidence/sample_findings.json      ← SHA256-hashed findings output
```

**IT Operational Duties:**

| Task | Frequency | Owner |
|------|-----------|-------|
| Export SAP user-role matrix → `data/user_roles.json` | Quarterly | IT Basis |
| Trigger or verify GitHub Actions GRC run | Daily (auto) | IT |
| Remediate HIGH/CRITICAL findings within SLA | Per finding | IT + Dept Head |
| Recertify privileged profiles | Quarterly | IT (CISO approval) |
| Lock dormant accounts flagged by KC-04 | Monthly | IT |
| Provide root cause for RECURRING findings | Per cycle | IT + IT Risk |

**Pipeline Triggers:**
- `cron: '0 0 * * *'` — daily at 07:00 WIB
- `push` to `rules/**`, `checks/**`, `remediation/**` — on-change
- `workflow_dispatch` — manual trigger with custom input file

**Critical Exit Conditions:**
- `exit 1` if any CRITICAL finding detected → blocks pipeline, alerts team
- SHA256 integrity check runs post-generation — alerts if tampered

---

<!-- ============================================================ -->
<!-- PAGE 3 — CTO & CEO                                           -->
<!-- ============================================================ -->

# SAP GRC-Lite — Executive Summary
### For CTO & CEO | Company X | 2026-Q1

---

## What Is This & Why It Matters

**SAP GRC-Lite** is Company X's automated compliance engine for SAP S/4HANA access controls. It replaces manual, spreadsheet-based UAM/UAR reviews with a code-driven, audit-ready system.

**Business Risk Addressed:**
> Uncontrolled SAP access = #1 fraud enabler in ERP environments. Segregation of Duties failures and unchecked privileged access expose Company X to financial misstatement, regulatory penalty, and reputational damage.

---

## What It Does — In Plain Terms

| Problem | What the System Does |
|---------|---------------------|
| Who has conflicting SAP roles (fraud risk)? | Checks 5 high-risk role combinations daily |
| Who has god-mode access (SAP_ALL)? | Flags any unauthorized privileged profile |
| Are inactive accounts creating ghost access? | Locks dormant accounts monthly |
| Is the same issue repeating? | Escalates recurring findings to CISO / Audit Committee |
| Can auditors trust the evidence? | SHA256-hashed, git-committed, tamper-evident trail |

---

## Value Delivered

**Compliance:** Meets ICoFR basis (Internal Reg. No. 11/2024), COSO 2013, PCAOB AS 2201/AS 1105
**Cost:** Zero additional tooling cost — runs on GitHub Actions (free tier eligible)
**Speed:** Daily automated checks vs. quarterly manual reviews previously
**Governance:** Full 3-line model embedded — IT operates, IT Risk owns, Internal Audit assures

**Management Action Required:**
- Approve deployment of SAP user-role data export to `data/` folder
- Confirm escalation contacts for CRITICAL findings (CISO, Audit Committee)
- Sign off on ruleset v2.0.0 as the approved ICoFR control baseline for 2026

---
*Prepared by: Internal Audit Division | Company X | Ruleset v2.0.0 | CONFIDENTIAL*
