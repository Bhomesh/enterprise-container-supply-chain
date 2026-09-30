import json
import os
import unittest
from src.policy_engine import PolicyEngine

class TestPolicyEngine(unittest.TestCase):
    def setUp(self):
        base_dir = os.path.dirname(__file__)
        self.rules_path = os.path.join(base_dir, "..", "policies", "security_gate_rules.yaml")
        self.waivers_path = os.path.join(base_dir, "..", "policies", "cve_waivers.yaml")
        self.license_path = os.path.join(base_dir, "..", "policies", "license_policy.yaml")
        self.fixtures_dir = os.path.join(base_dir, "fixtures")

        self.engine = PolicyEngine(
            rules_path=self.rules_path,
            waivers_path=self.waivers_path,
            license_policy_path=self.license_path
        )

    def test_clean_image_passes(self):
        with open(os.path.join(self.fixtures_dir, "trivy_sample_clean.json"), "r") as f:
            data = json.load(f)
        vulns = self.engine.parse_trivy_report(data)
        result = self.engine.evaluate(vulns)
        self.assertTrue(result.is_approved)
        self.assertEqual(result.critical_count, 0)
        self.assertEqual(len(result.violations), 0)

    def test_critical_image_fails_and_flags_kev(self):
        with open(os.path.join(self.fixtures_dir, "trivy_sample_critical.json"), "r") as f:
            data = json.load(f)
        vulns = self.engine.parse_trivy_report(data)
        result = self.engine.evaluate(vulns)
        self.assertFalse(result.is_approved)
        self.assertEqual(result.critical_count, 2)
        # Should detect CISA KEV for Log4j and RCE violation
        violations_str = " ".join(result.violations)
        self.assertIn("CVE-2021-44228", violations_str)
        self.assertIn("CISA KEV", violations_str)

    def test_waived_cve_passes(self):
        with open(os.path.join(self.fixtures_dir, "trivy_sample_waived.json"), "r") as f:
            data = json.load(f)
        vulns = self.engine.parse_trivy_report(data)
        result = self.engine.evaluate(vulns)
        # CVE-2023-44487 is actively in cve_waivers.yaml
        self.assertTrue(result.is_approved)
        self.assertEqual(result.waived_count, 1)
        self.assertIn("CVE-2023-44487", result.waived_cves)

    def test_license_violation(self):
        result = self.engine.evaluate([], licenses=["AGPL-3.0-only"])
        self.assertFalse(result.is_approved)
        self.assertIn("License Violation", result.violations[0])

if __name__ == "__main__":
    unittest.main()
