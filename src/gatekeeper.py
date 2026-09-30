#!/usr/bin/env python3
"""
Container Security Gatekeeper CLI
Ingests Trivy or Grype scan JSON, applies policy rules and waivers,
and issues cryptographic pass/fail admission verdict.
"""

import argparse
import json
import logging
import sys
from typing import Optional

from src.policy_engine import PolicyEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("gatekeeper")

def main():
    parser = argparse.ArgumentParser(description="Container Security Gatekeeper")
    parser.add_argument("--report", required=True, help="Path to Trivy scan JSON report")
    parser.add_argument("--policy", default="policies/security_gate_rules.yaml", help="Path to policy YAML")
    parser.add_argument("--waivers", default="policies/cve_waivers.yaml", help="Path to waivers YAML")
    parser.add_argument("--licenses", default="policies/license_policy.yaml", help="Path to license policy YAML")
    parser.add_argument("--output-verdict", help="Path to output verdict JSON")
    args = parser.parse_args()

    logger.info(f"Loading scan report from {args.report} ...")
    try:
        with open(args.report, "r", encoding="utf-8") as f:
            report_data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to read report: {e}")
        sys.exit(2)

    engine = PolicyEngine(
        rules_path=args.policy,
        waivers_path=args.waivers,
        license_policy_path=args.licenses
    )

    vulns = engine.parse_trivy_report(report_data)
    logger.info(f"Parsed {len(vulns)} total vulnerability entries from report.")

    result = engine.evaluate(vulns)

    print("\n" + "="*60)
    print("       CONTAINER SECURITY GATING VERDICT")
    print("="*60)
    print(f"Status:   {'[APPROVED]' if result.is_approved else '[REJECTED]'}")
    print(f"Critical: {result.critical_count}")
    print(f"High:     {result.high_count}")
    print(f"Medium:   {result.medium_count}")
    print(f"Low:      {result.low_count}")
    print(f"Waived:   {result.waived_count} ({', '.join(result.waived_cves) or 'None'})")

    if result.violations:
        print("\nPolicy Violations:")
        for v in result.violations:
            print(f"  ❌ {v}")
    print("="*60 + "\n")

    if args.output_verdict:
        with open(args.output_verdict, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)

    if not result.is_approved:
        logger.error("Image failed security gating policy! Halting promotion.")
        sys.exit(1)
    else:
        logger.info("Image passed all security gates. Cleared for signing and promotion!")
        sys.exit(0)

if __name__ == "__main__":
    main()
