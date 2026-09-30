#!/usr/bin/env python3
"""
Vulnerability Gating Policy Engine
Evaluates container scan artifacts against enterprise security policies,
active waivers, CVSS thresholds, and license compliance rules.
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("policy_engine")

# Known CISA KEV sample indicators
CISA_KEV_DATABASE = {
    "CVE-2021-44228", # Log4Shell
    "CVE-2023-44487", # HTTP/2 Rapid Reset
    "CVE-2022-22965", # Spring4Shell
    "CVE-2023-38606", # WebKit
    "CVE-2024-3094",  # XZ Backdoor
}

def load_yaml_or_json(file_path: str) -> Dict[str, Any]:
    """Loads YAML using PyYAML if available, or simple standard-library fallback parser."""
    if not os.path.exists(file_path):
        return {}
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    try:
        import yaml
        return yaml.safe_load(content) or {}
    except ImportError:
        # Simple fallback parser for key-value and list structures
        result = {}
        current_list_key = None
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.endswith(":") and not line.startswith("-"):
                current_list_key = line[:-1].strip()
                result[current_list_key] = []
            elif line.startswith("- ") and current_list_key:
                val = line[2:].strip().strip('"').strip("'")
                result[current_list_key].append(val)
            elif ":" in line and not line.startswith("-"):
                parts = line.split(":", 1)
                k = parts[0].strip()
                v = parts[1].strip().strip('"').strip("'")
                if v.lower() == "true":
                    result[k] = True
                elif v.lower() == "false":
                    result[k] = False
                elif v.isdigit():
                    result[k] = int(v)
                else:
                    try:
                        result[k] = float(v)
                    except ValueError:
                        result[k] = v
        return result

class VulnerabilityRecord:
    def __init__(self, cve_id: str, package: str, installed_version: str,
                 fixed_version: Optional[str], severity: str, cvss_score: float = 0.0,
                 title: str = "", is_rce: bool = False):
        self.cve_id = cve_id
        self.package = package
        self.installed_version = installed_version
        self.fixed_version = fixed_version
        self.severity = severity.upper()
        self.cvss_score = cvss_score
        self.title = title
        self.is_rce = is_rce

class PolicyEvaluationResult:
    def __init__(self, is_approved: bool, critical_count: int, high_count: int,
                 medium_count: int, low_count: int, waived_count: int,
                 violations: List[str], waived_cves: List[str]):
        self.is_approved = is_approved
        self.critical_count = critical_count
        self.high_count = high_count
        self.medium_count = medium_count
        self.low_count = low_count
        self.waived_count = waived_count
        self.violations = violations
        self.waived_cves = waived_cves

    def to_dict(self) -> Dict[str, Any]:
        return {
            "approved": self.is_approved,
            "counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "waived": self.waived_count,
            },
            "violations": self.violations,
            "waived_cves": self.waived_cves,
        }

class PolicyEngine:
    def __init__(self, rules_path: Optional[str] = None,
                 waivers_path: Optional[str] = None,
                 license_policy_path: Optional[str] = None):
        self.rules = load_yaml_or_json(rules_path) if rules_path else {}
        self.waivers_data = load_yaml_or_json(waivers_path) if waivers_path else {}
        self.license_policy = load_yaml_or_json(license_policy_path) if license_policy_path else {}
        self.active_waivers = self._parse_active_waivers()

    def _parse_active_waivers(self) -> Dict[str, Dict]:
        active = {}
        now = datetime.now(timezone.utc).date()
        waiver_list = self.waivers_data.get("waivers", [])
        if isinstance(waiver_list, list):
            for w in waiver_list:
                if not isinstance(w, dict):
                    continue
                cve = w.get("cve_id")
                expires_str = w.get("expires_at", "")
                if cve and expires_str:
                    try:
                        exp_date = datetime.strptime(expires_str, "%Y-%m-%d").date()
                        if exp_date >= now:
                            active[cve] = w
                        else:
                            logger.warning(f"Waiver for {cve} expired on {expires_str}!")
                    except ValueError:
                        pass
        return active

    def parse_trivy_report(self, report_data: Dict[str, Any]) -> List[VulnerabilityRecord]:
        records = []
        results = report_data.get("Results", [])
        for res in results:
            for vuln in res.get("Vulnerabilities", []) or []:
                cve_id = vuln.get("VulnerabilityID", "UNKNOWN")
                pkg = vuln.get("PkgName", "unknown")
                installed_ver = vuln.get("InstalledVersion", "unknown")
                fixed_ver = vuln.get("FixedVersion")
                severity = vuln.get("Severity", "UNKNOWN")
                cvss_data = vuln.get("CVSS", {})
                cvss_score = 0.0
                for source in ["nvd", "redhat", "ghsa"]:
                    if source in cvss_data and "V3Score" in cvss_data[source]:
                        cvss_score = float(cvss_data[source]["V3Score"])
                        break
                title = vuln.get("Title", "")
                desc = vuln.get("Description", "").lower()
                is_rce = "remote code execution" in desc or "arbitrary code" in desc
                records.append(VulnerabilityRecord(
                    cve_id=cve_id,
                    package=pkg,
                    installed_version=installed_ver,
                    fixed_version=fixed_ver,
                    severity=severity,
                    cvss_score=cvss_score,
                    title=title,
                    is_rce=is_rce,
                ))
        return records

    def evaluate(self, vulnerabilities: List[VulnerabilityRecord], licenses: Optional[List[str]] = None) -> PolicyEvaluationResult:
        crit_count = 0
        high_count = 0
        med_count = 0
        low_count = 0
        waived_count = 0

        violations = []
        waived_cves = []

        rules = self.rules.get("rules", self.rules)
        max_crit = rules.get("max_critical_cves", 0)
        max_high = rules.get("max_high_cves", 0)
        max_med = rules.get("max_medium_cves", 5)
        block_kev = rules.get("block_cisa_kev", True)
        block_rce = rules.get("block_remote_code_execution", True)

        for v in vulnerabilities:
            if v.cve_id in self.active_waivers:
                waived_count += 1
                waived_cves.append(v.cve_id)
                logger.info(f"CVE {v.cve_id} is waived: {self.active_waivers[v.cve_id].get('reason')}")
                continue

            # Check CISA KEV
            if block_kev and v.cve_id in CISA_KEV_DATABASE:
                violations.append(f"CISA KEV Exploit Violation: {v.cve_id} ({v.package}) is actively exploited in the wild")

            # Check RCE
            if block_rce and v.is_rce and v.severity in ["CRITICAL", "HIGH"]:
                violations.append(f"RCE Violation: {v.cve_id} in {v.package} allows Remote Code Execution")

            if v.severity == "CRITICAL":
                crit_count += 1
            elif v.severity == "HIGH":
                high_count += 1
            elif v.severity == "MEDIUM":
                med_count += 1
            elif v.severity == "LOW":
                low_count += 1

        if crit_count > max_crit:
            violations.append(f"Threshold Violation: Found {crit_count} Critical CVEs (Max allowed: {max_crit})")
        if high_count > max_high:
            violations.append(f"Threshold Violation: Found {high_count} High CVEs (Max allowed: {max_high})")
        if med_count > max_med:
            violations.append(f"Threshold Violation: Found {med_count} Medium CVEs (Max allowed: {max_med})")

        # License checks
        if licenses and self.license_policy:
            denied = set(self.license_policy.get("denied_licenses", []))
            for lic in licenses:
                if lic in denied:
                    violations.append(f"License Violation: Package with forbidden license '{lic}' detected")

        is_approved = len(violations) == 0
        return PolicyEvaluationResult(
            is_approved=is_approved,
            critical_count=crit_count,
            high_count=high_count,
            medium_count=med_count,
            low_count=low_count,
            waived_count=waived_count,
            violations=violations,
            waived_cves=waived_cves,
        )
