import os
import unittest
from src.promotion_daemon import PromotionDaemon
from src.slack_notifier import SlackNotifier

class TestPromotionDaemon(unittest.TestCase):
    def setUp(self):
        base_dir = os.path.dirname(__file__)
        self.clean_report = os.path.join(base_dir, "fixtures", "trivy_sample_clean.json")
        self.critical_report = os.path.join(base_dir, "fixtures", "trivy_sample_critical.json")
        self.daemon = PromotionDaemon(
            policy_path=os.path.join(base_dir, "..", "policies", "security_gate_rules.yaml"),
            waivers_path=os.path.join(base_dir, "..", "policies", "cve_waivers.yaml"),
            license_path=os.path.join(base_dir, "..", "policies", "license_policy.yaml")
        )
        self.notifier = SlackNotifier()

    def test_promotion_approved_for_clean_image(self):
        result = self.daemon.promote(
            intake_image="intake.registry/app:1.0.0",
            golden_image="golden.registry/app:1.0.0",
            scan_report_path=self.clean_report,
            digest="sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
        )
        self.assertTrue(result)

    def test_promotion_rejected_for_critical_image(self):
        result = self.daemon.promote(
            intake_image="intake.registry/app:bad",
            golden_image="golden.registry/app:bad",
            scan_report_path=self.critical_report,
            digest="sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        )
        self.assertFalse(result)

    def test_slack_card_builders(self):
        approval = self.notifier.build_approval_card(
            "intake/app:1", "golden/app:1", "sha256:abc",
            {"critical": 0, "high": 0, "medium": 0, "low": 0}, []
        )
        self.assertEqual(approval["blocks"][0]["text"]["text"], "🛡️ Container Supply Chain: Image Cleared & Promoted")

        rejection = self.notifier.build_rejection_card(
            "intake/app:bad", ["Critical CVE detected"], {"critical": 1, "high": 0}
        )
        self.assertEqual(rejection["blocks"][0]["text"]["text"], "🚨 Security Gate Blocked Container Promotion")

if __name__ == "__main__":
    unittest.main()
