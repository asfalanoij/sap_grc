#!/usr/bin/env python3
"""
SAP GRC-Lite Rules Engine - Company X
Version: 2.0.0
Purpose: Evaluate SAP user-role data against GRC ruleset YAML definitions.
Outputs: SHA256-hashed findings JSON committed to evidence/

Usage:
    python checks/run_checks.py --input data/user_roles.json --output evidence/findings.json
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml


DEFAULT_RULES_DIR = Path("rules")
DEFAULT_OUTPUT = Path("evidence/findings.json")
CYCLE_ID = datetime.now(timezone.utc).strftime("%Y-Q") + str((datetime.now(timezone.utc).month - 1) // 3 + 1)


def load_yaml(path: Path) -> dict:
    """Load a YAML file and return as dict."""
    with open(path, "r") as f:
        return yaml.safe_load(f)


def load_user_roles(path: Path) -> list:
    """Load user-role data from JSON file."""
    with open(path, "r") as f:
        return json.load(f)


def check_sod_violations(user_roles: list, sod_rules: dict) -> list:
    """
    Check for SoD violations.
    user_roles: list of {user_id, roles: [...]}
    sod_rules: parsed sod_matrix.yaml
    Returns list of findings.
    """
    findings = []
    conflict_pairs = sod_rules.get("conflict_pairs", [])

    for user in user_roles:
        user_id = user.get("user_id")
        roles = set(user.get("roles", []))

        for conflict in conflict_pairs:
            role_a = conflict.get("role_a")
            role_b = conflict.get("role_b")

            if role_a in roles and role_b in roles:
                findings.append({
                    "finding_type": "SOD_VIOLATION",
                    "rule_id": conflict["id"],
                    "rule_name": conflict["name"],
                    "user_id": user_id,
                    "roles_in_conflict": [role_a, role_b],
                    "risk_level": conflict["risk_level"],
                    "icofr_ref": conflict.get("icofr_ref"),
                    "description": conflict.get("description"),
                    "remediation_action": conflict.get("remediation_action"),
                    "recurrence_policy": conflict.get("recurrence_policy"),
                    "detection_date": datetime.now(timezone.utc).isoformat(),
                    "cycle_id": CYCLE_ID,
                    "status": "OPEN",
                    "recurrence_count": 0,
                    "recurrence_flag": "NONE"
                })

    return findings


def check_privileged_access(user_roles: list, pa_rules: dict) -> list:
    """
    Check for privileged access violations.
    """
    findings = []
    privileged_profiles = pa_rules.get("privileged_profiles", [])

    for user in user_roles:
        user_id = user.get("user_id")
        profiles = set(user.get("profiles", []))
        roles = set(user.get("roles", []))

        for pp in privileged_profiles:
            profile = pp["profile"]
            allowed_users = set(pp.get("allowed_users", []))
            allowed_roles = set(pp.get("allowed_roles", []))

            if profile in profiles:
                if user_id not in allowed_users and not roles.intersection(allowed_roles):
                    findings.append({
                        "finding_type": "PRIVILEGED_ACCESS_VIOLATION",
                        "rule_id": pp["id"],
                        "rule_name": f"Unauthorized {profile} assignment",
                        "user_id": user_id,
                        "profile": profile,
                        "risk_level": pp["risk_level"],
                        "description": pp.get("description"),
                        "detection_date": datetime.now(timezone.utc).isoformat(),
                        "cycle_id": CYCLE_ID,
                        "status": "OPEN",
                        "recurrence_count": 0,
                        "recurrence_flag": "NONE"
                    })

    return findings


def check_dormant_accounts(user_roles: list, da_rules: dict) -> list:
    """
    Check for dormant accounts.
    Expects user entries with last_login_date field.
    """
    findings = []
    thresholds = da_rules.get("dormancy_thresholds", {})
    today = datetime.now(timezone.utc).date()

    for user in user_roles:
        user_id = user.get("user_id")
        account_type = user.get("account_type", "standard").lower()
        last_login_str = user.get("last_login_date")
        hr_status = user.get("hr_status", "ACTIVE")

        # Check terminated employee with active account
        if hr_status == "TERMINATED" and user.get("account_status") == "ACTIVE":
            findings.append({
                "finding_type": "TERMINATED_EMPLOYEE_ACTIVE",
                "rule_id": "DA-RULE-003",
                "rule_name": "Terminated employee account still active",
                "user_id": user_id,
                "risk_level": "CRITICAL",
                "detection_date": datetime.now(timezone.utc).isoformat(),
                "cycle_id": CYCLE_ID,
                "status": "OPEN",
                "recurrence_count": 0,
                "recurrence_flag": "NONE"
            })
            continue

        if last_login_str:
            last_login = datetime.fromisoformat(last_login_str).date()
            days_inactive = (today - last_login).days

            threshold_key = f"{account_type}_user"
            threshold = thresholds.get(threshold_key, thresholds.get("standard_user", {}))
            max_days = threshold.get("inactive_days", 90)

            if days_inactive > max_days:
                findings.append({
                    "finding_type": "DORMANT_ACCOUNT",
                    "rule_id": "DA-RULE-001" if account_type == "standard" else "DA-RULE-002",
                    "rule_name": f"{account_type.title()} user inactive {days_inactive} days",
                    "user_id": user_id,
                    "account_type": account_type,
                    "days_inactive": days_inactive,
                    "threshold": max_days,
                    "risk_level": threshold.get("risk_level", "MEDIUM"),
                    "detection_date": datetime.now(timezone.utc).isoformat(),
                    "cycle_id": CYCLE_ID,
                    "status": "OPEN",
                    "recurrence_count": 0,
                    "recurrence_flag": "NONE"
                })

    return findings


def hash_findings(findings: list) -> str:
    """Generate SHA256 hash of findings list."""
    findings_str = json.dumps(findings, sort_keys=True)
    return hashlib.sha256(findings_str.encode()).hexdigest()


def write_findings(findings: list, output_path: Path):
    """Write findings to JSON file with metadata."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    output = {
        "metadata": {
            "organization": "Company X",
            "system": "SAP S/4HANA Client 300",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "cycle_id": CYCLE_ID,
            "ruleset_version": "2.0.0",
            "total_findings": len(findings),
            "critical_count": sum(1 for f in findings if f.get("risk_level") == "CRITICAL"),
            "high_count": sum(1 for f in findings if f.get("risk_level") == "HIGH"),
            "medium_count": sum(1 for f in findings if f.get("risk_level") == "MEDIUM"),
            "low_count": sum(1 for f in findings if f.get("risk_level") == "LOW"),
        },
        "findings": findings,
        "sha256": hash_findings(findings)
    }

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"[GRC] Findings written to {output_path}")
    print(f"[GRC] SHA256: {output['sha256']}")
    print(f"[GRC] Total findings: {len(findings)}")


def main():
    parser = argparse.ArgumentParser(description="SAP GRC-Lite Rules Engine - Company X")
    parser.add_argument("--input", type=Path, default=Path("data/user_roles.json"),
                        help="Path to user-role JSON data")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT,
                        help="Path to output findings JSON")
    parser.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES_DIR,
                        help="Path to rules directory")
    args = parser.parse_args()

    print(f"[GRC] SAP GRC-Lite Rules Engine v2.0.0 - Company X")
    print(f"[GRC] Cycle: {CYCLE_ID}")
    print(f"[GRC] Loading user-role data from {args.input}")

    if not args.input.exists():
        print(f"[GRC] ERROR: Input file not found: {args.input}")
        sys.exit(1)

    user_roles = load_user_roles(args.input)
    print(f"[GRC] Loaded {len(user_roles)} user records")

    all_findings = []

    # SoD checks
    sod_path = args.rules_dir / "sod_matrix.yaml"
    if sod_path.exists():
        sod_rules = load_yaml(sod_path)
        sod_findings = check_sod_violations(user_roles, sod_rules)
        print(f"[GRC] SoD violations found: {len(sod_findings)}")
        all_findings.extend(sod_findings)

    # Privileged access checks
    pa_path = args.rules_dir / "privileged_access.yaml"
    if pa_path.exists():
        pa_rules = load_yaml(pa_path)
        pa_findings = check_privileged_access(user_roles, pa_rules)
        print(f"[GRC] Privileged access violations found: {len(pa_findings)}")
        all_findings.extend(pa_findings)

    # Dormant account checks
    da_path = args.rules_dir / "dormant_accounts.yaml"
    if da_path.exists():
        da_rules = load_yaml(da_path)
        da_findings = check_dormant_accounts(user_roles, da_rules)
        print(f"[GRC] Dormant account violations found: {len(da_findings)}")
        all_findings.extend(da_findings)

    write_findings(all_findings, args.output)

    # Exit with non-zero if critical findings
    critical_count = sum(1 for f in all_findings if f.get("risk_level") == "CRITICAL")
    if critical_count > 0:
        print(f"[GRC] WARNING: {critical_count} CRITICAL findings require immediate attention!")
        sys.exit(1)


if __name__ == "__main__":
    main()
