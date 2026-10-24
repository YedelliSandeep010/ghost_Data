"""
Policy Engine.
Applies deletion rules from deletion_rules.csv across all data categories and systems.
Determines required actions, permissible retained identifiers, and tombstone requirements.
"""

from typing import Dict, Any, Optional, Tuple


class PolicyEngine:
    # Rule definitions
    CATEGORY_ACTIONS = {
        "USER_PROFILE": "DELETE",
        "SECONDARY_IDENTIFIER": "DELETE",
        "SEARCH_INDEX_ENTRY": "DELETE",
        "CACHE_ENTRY": "DELETE",
        "SUPPORT_MESSAGE": "REDACT",
        "SUPPORT_ATTACHMENT": "DELETE",
        "ANALYTICS_PROFILE": "ANONYMIZE",
        "PRODUCT_TELEMETRY": "ANONYMIZE",
        "USER_EXPORT": "DELETE",
        "MARKETING_PROFILE": "DELETE",
        "EMAIL_DELIVERY_LOG": "REDACT",
        "SECURITY_AUDIT_LOG": "RETAIN",
        "LEGAL_HOLD_RECORD": "RETAIN",
        "BACKUP_ARCHIVE": "RETAIN",
        "ACCOUNT_TOMBSTONE": "REDACT",
    }

    # Default mapping by system and resource prefix if category not explicitly given
    SYSTEM_CATEGORY_MAP = {
        "account_service": "USER_PROFILE",
        "search_service": "SEARCH_INDEX_ENTRY",
        "identity_service": "ACCOUNT_TOMBSTONE",
        "export_service": "USER_EXPORT",
        "marketing_platform": "MARKETING_PROFILE",
        "security_service": "SECURITY_AUDIT_LOG",
        "backup_service": "BACKUP_ARCHIVE",
    }

    @classmethod
    def get_required_action(cls, system_id: str, resource_id: str, category: Optional[str] = None) -> str:
        """Returns the required policy action: DELETE, REDACT, ANONYMIZE, or RETAIN."""
        if category and category in cls.CATEGORY_ACTIONS:
            return cls.CATEGORY_ACTIONS[category]

        if resource_id.startswith("tombstone_"):
            return "REDACT"
        if resource_id.startswith("account_"):
            return "DELETE"
        if resource_id.startswith("search_"):
            return "DELETE"
        if resource_id.startswith("export_"):
            return "DELETE"
        if resource_id.startswith("analytics_"):
            return "ANONYMIZE"
        if resource_id.startswith("support_"):
            # If not specified, support conversations need REDACT
            return "REDACT"
        if resource_id.startswith("backup_"):
            return "RETAIN"
        if resource_id.startswith("audit_record_"):
            return "RETAIN"

        cat = cls.SYSTEM_CATEGORY_MAP.get(system_id, "USER_PROFILE")
        return cls.CATEGORY_ACTIONS.get(cat, "DELETE")

    @classmethod
    def get_remediation_operation(cls, system_id: str, resource_id: str, finding_op: str) -> str:
        """Determines the appropriate remediation operation."""
        if finding_op == "REPORT_ACTIVE_DATA_FLOW" or system_id == "integration_service" or resource_id.startswith("data_flow_"):
            return "DISABLE_DATA_FLOW"
        if finding_op == "REPORT_RESTORE_RISK" or system_id == "backup_service" or resource_id.startswith("backup_"):
            return "BLOCK_RESTORE"

        action = cls.get_required_action(system_id, resource_id)
        if action == "DELETE":
            return "DELETE_RECORD"
        elif action == "REDACT":
            return "REDACT_RECORD"
        elif action == "ANONYMIZE":
            return "ANONYMIZE_RECORD"
        return "DELETE_RECORD"

    @classmethod
    def get_verification_operation(cls, system_id: str, resource_id: str, remediation_op: Optional[str] = None) -> Tuple[str, str]:
        """
        Returns (operation, state) for verification step.
        """
        if remediation_op == "DISABLE_DATA_FLOW" or system_id == "integration_service" or resource_id.startswith("data_flow_"):
            return "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
        if remediation_op == "BLOCK_RESTORE" or (system_id == "backup_service" and resource_id.startswith("backup_")):
            return "VERIFY_RESTORE_BLOCKED", "BLOCKED"

        if system_id == "security_service" or resource_id.startswith("audit_record_"):
            return "VERIFY_RECORD_PRESENT", "PRESENT"

        if remediation_op == "DELETE_RECORD":
            return "VERIFY_RECORD_ABSENT", "ABSENT"
        if remediation_op == "REDACT_RECORD":
            return "VERIFY_RECORD_REDACTED", "REDACTED"
        if remediation_op == "ANONYMIZE_RECORD":
            return "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"

        action = cls.get_required_action(system_id, resource_id)
        if action == "DELETE":
            return "VERIFY_RECORD_ABSENT", "ABSENT"
        elif action == "REDACT":
            return "VERIFY_RECORD_REDACTED", "REDACTED"
        elif action == "ANONYMIZE":
            return "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
        elif action == "RETAIN":
            return "VERIFY_RECORD_PRESENT", "PRESENT"

        return "VERIFY_RECORD_ABSENT", "ABSENT"
