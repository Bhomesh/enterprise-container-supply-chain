#!/usr/bin/env python3
"""
Slack Block Kit Alert Notifier
Formats and sends rich security gate verdicts, promotion events,
and vulnerability alert cards to enterprise webhook channels.
"""

import json
import logging
import os
import urllib.request
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("slack_notifier")

class SlackNotifier:
    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL")

    def build_approval_card(self, image_ref: str, golden_ref: str, digest: str,
                            cve_counts: Dict[str, int], waived_cves: List[str]) -> Dict[str, Any]:
        return {
            "text": f"✅ Container Image Promoted: {golden_ref}",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🛡️ Container Supply Chain: Image Cleared & Promoted",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Source Image:*\n`{image_ref}`"},
                        {"type": "mrkdwn", "text": f"*Golden Target:*\n`{golden_ref}`"},
                        {"type": "mrkdwn", "text": f"*Digest:*\n`{digest[:19]}...`"},
                        {"type": "mrkdwn", "text": f"*SLSA Provenance:*\nLevel 3 (Attested)"}
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Vulnerability Summary:*\n• Critical: *{cve_counts.get('critical', 0)}*\n• High: *{cve_counts.get('high', 0)}*\n• Medium: *{cve_counts.get('medium', 0)}*\n• Low: *{cve_counts.get('low', 0)}*\n• Waived Exceptions: *{len(waived_cves)}* (`{', '.join(waived_cves) or 'None'}`)"
                    }
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": "🔐 Cryptographically signed via Cosign • In-Toto SBOM attached"
                        }
                    ]
                }
            ]
        }

    def build_rejection_card(self, image_ref: str, violations: List[str], cve_counts: Dict[str, int]) -> Dict[str, Any]:
        violation_text = "\n".join([f"• ❌ {v}" for v in violations[:5]])
        if len(violations) > 5:
            violation_text += f"\n• ... and {len(violations) - 5} more violations"

        return {
            "text": f"🚨 Security Gate Violation: {image_ref}",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🚨 Security Gate Blocked Container Promotion",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Rejected Image:*\n`{image_ref}`"},
                        {"type": "mrkdwn", "text": f"*Action:*\nQuarantined in Intake Registry"},
                        {"type": "mrkdwn", "text": f"*Critical CVEs:*\n*{cve_counts.get('critical', 0)}*"},
                        {"type": "mrkdwn", "text": f"*High CVEs:*\n*{cve_counts.get('high', 0)}*"}
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Policy Violations:*\n{violation_text}"
                    }
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": "⚠️ To request a temporary exception, submit a signed waiver to `policies/cve_waivers.yaml`"
                        }
                    ]
                }
            ]
        }

    def send_notification(self, payload: Dict[str, Any]) -> bool:
        if not self.webhook_url:
            logger.info("SLACK_WEBHOOK_URL not configured. Notification output logged to stdout:")
            print(json.dumps(payload, indent=2))
            return True

        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    logger.info("Slack alert dispatched successfully.")
                    return True
        except Exception as e:
            logger.error(f"Failed to dispatch Slack alert: {e}")
        return False
