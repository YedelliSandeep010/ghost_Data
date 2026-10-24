"""
Unit and integration tests for Ghost Data Deletion Audit Agent.
"""

import unittest
import os
import sys

# Ensure audit_engine is in sys.path
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(TEST_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from audit_engine.models import AuditStep, DeletionRequest
from audit_engine.intent_analyzer import IntentAnalyzer
from audit_engine.policy_engine import PolicyEngine
from audit_engine.step_serializer import StepSerializer
from audit_engine.identity_resolver import IdentityResolver


class TestGhostDataAuditEngine(unittest.TestCase):
    def test_intent_analyzer_deletion(self):
        """Verifies that deletion requests across languages are recognized as authorized."""
        # English
        auth, _ = IntentAnalyzer.is_deletion_authorized("Please close my account and permanently delete my data.")
        self.assertTrue(auth)

        # Spanish
        auth, _ = IntentAnalyzer.is_deletion_authorized("Solicito la eliminación permanente de mi cuenta y mis datos.")
        self.assertTrue(auth)

        # French
        auth, _ = IntentAnalyzer.is_deletion_authorized("Je demande la suppression définitive du compte associé.")
        self.assertTrue(auth)

        # Japanese
        auth, _ = IntentAnalyzer.is_deletion_authorized("このメールアドレスに関連するアカウントの完全な削除を依頼します。")
        self.assertTrue(auth)

        # Korean
        auth, _ = IntentAnalyzer.is_deletion_authorized("이 이메일 주소에 연결된 계정의 영구 삭제를 요청합니다.")
        self.assertTrue(auth)

    def test_intent_analyzer_non_deletion(self):
        """Verifies that non-deletion requests are flagged as NOT_APPLICABLE."""
        # Phone update only
        auth, reason = IntentAnalyzer.is_deletion_authorized(
            "The mobile number on my profile is out of date. Please replace it with the new one and leave the account active."
        )
        self.assertFalse(auth)

        # Data download / export only
        auth, reason = IntentAnalyzer.is_deletion_authorized(
            "I'd like to download my account information in a portable format. Please keep the account as it is."
        )
        self.assertFalse(auth)

        # Copy of invoices
        auth, reason = IntentAnalyzer.is_deletion_authorized(
            "I need a copy of last year's invoices for my records. Please leave my profile and purchase history in place."
        )
        self.assertFalse(auth)

        # Email change
        auth, reason = IntentAnalyzer.is_deletion_authorized(
            "Please change the email address used for this account. I want to continue using the service."
        )
        self.assertFalse(auth)

    def test_policy_engine_categories(self):
        """Tests data category actions under deletion policy rules."""
        self.assertEqual(PolicyEngine.get_required_action("account_service", "account_001"), "DELETE")
        self.assertEqual(PolicyEngine.get_required_action("search_service", "search_001"), "DELETE")
        self.assertEqual(PolicyEngine.get_required_action("export_service", "export_001"), "DELETE")
        self.assertEqual(PolicyEngine.get_required_action("analytics_platform", "analytics_001"), "ANONYMIZE")
        self.assertEqual(PolicyEngine.get_required_action("identity_service", "tombstone_001"), "REDACT")
        self.assertEqual(PolicyEngine.get_required_action("security_service", "audit_record_001"), "RETAIN")
        self.assertEqual(PolicyEngine.get_required_action("backup_service", "backup_001"), "RETAIN")

    def test_step_serializer_ordering(self):
        """Verifies phase and operation ordering contract: FINDING -> REMEDIATION -> VERIFICATION."""
        raw_steps = [
            AuditStep(0, "VERIFICATION", "account_service", "account_005", "VERIFY_RECORD_ABSENT", "ABSENT", ""),
            AuditStep(0, "FINDING", "account_service", "account_005", "REPORT_REMAINING_RECORD", "PRESENT", "ev_01"),
            AuditStep(0, "REMEDIATION", "account_service", "account_005", "DELETE_RECORD", "ABSENT", ""),
        ]

        sorted_steps = StepSerializer.sort_and_number_steps(raw_steps)
        self.assertEqual(len(sorted_steps), 3)

        # Check consecutive 1-based numbering
        self.assertEqual(sorted_steps[0].step_no, 1)
        self.assertEqual(sorted_steps[1].step_no, 2)
        self.assertEqual(sorted_steps[2].step_no, 3)

        # Check phase ordering
        self.assertEqual(sorted_steps[0].phase, "FINDING")
        self.assertEqual(sorted_steps[1].phase, "REMEDIATION")
        self.assertEqual(sorted_steps[2].phase, "VERIFICATION")

    def test_step_serializer_json_validity(self):
        """Verifies JSON output format."""
        steps = [
            AuditStep(1, "VERIFICATION", "account_service", "account_001", "VERIFY_RECORD_ABSENT", "ABSENT", "evidence_54")
        ]
        json_str = StepSerializer.serialize_to_json(steps)
        self.assertIn('"step_no":1', json_str)
        self.assertIn('"phase":"VERIFICATION"', json_str)
        self.assertIn('"evidence_id":"evidence_54"', json_str)


if __name__ == "__main__":
    unittest.main()
