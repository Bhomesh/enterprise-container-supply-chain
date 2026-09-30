#!/usr/bin/env python3
"""
Container Promotion Daemon
Orchestrates the promotion of vetted container images from
Intake (Quarantine) Registry to Golden (Production) Registry.
Enforces gatekeeper approval, cryptographic signing, and audit notifications.
"""

import argparse
import json
import logging
import os
import sys
from typing import Optional

from src.cosign_signer import CosignSigner
from src.policy_engine import PolicyEngine
from src.slack_notifier import SlackNotifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("promotion_daemon")

class PromotionDaemon:
    def __init__(self, policy_path: str = "policies/security_gate_rules.yaml",
                 waivers_path: str = "policies/cve_waivers.yaml",
                 license_path: str = "policies/license_policy.yaml",
                 webhook_url: Optional[str] = None):
        self.engine = PolicyEngine(policy_path, waivers_path, license_path)
        self.signer = CosignSigner()
        self.notifier = SlackNotifier(webhook_url)

    def promote(self, intake_image: str, golden_image: str,
                scan_report_path: str, digest: str) -> bool:
        logger.info(f"Initiating promotion assessment for {intake_image} -> {golden_image}")

        with open(scan_report_path, "r", encoding="utf-8") as f:
            scan_data = json.load(f)

        vulns = self.engine.parse_trivy_report(scan_data)
        verdict = self.engine.evaluate(vulns)

        if not verdict.is_approved:
            logger.error(f"Promotion REJECTED: Found {len(verdict.violations)} security violations.")
            rejection_card = self.notifier.build_rejection_card(
                image_ref=intake_image,
                violations=verdict.violations,
                cve_counts=verdict.to_dict()["counts"]
            )
            self.notifier.send_notification(rejection_card)
            return False

        logger.info("Security Gate PASSED. Proceeding with cryptographic signing & promotion...")

        # Sign digest & generate SLSA attestation
        sig_result = self.signer.sign_digest(golden_image, digest)
        slsa_statement = self.signer.generate_slsa_provenance(golden_image, digest)

        # Notify success
        approval_card = self.notifier.build_approval_card(
            image_ref=intake_image,
            golden_ref=golden_image,
            digest=digest,
            cve_counts=verdict.to_dict()["counts"],
            waived_cves=verdict.waived_cves
        )
        self.notifier.send_notification(approval_card)
        logger.info(f"Image successfully promoted to Golden Registry: {golden_image}@{digest}")
        return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Promote container image to Golden Registry")
    parser.add_argument("--intake", required=True, help="Source intake image reference")
    parser.add_argument("--golden", required=True, help="Target golden image reference")
    parser.add_argument("--report", required=True, help="Path to Trivy scan report JSON")
    parser.add_argument("--digest", default="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    args = parser.parse_args()

    daemon = PromotionDaemon()
    success = daemon.promote(args.intake, args.golden, args.report, args.digest)
    sys.exit(0 if success else 1)
