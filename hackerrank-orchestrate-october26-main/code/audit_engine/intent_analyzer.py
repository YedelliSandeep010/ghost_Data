"""
Intent Analyzer.
Determines whether a user request authorizes account or personal data deletion.
Distinguishes deletion requests from access, export, rectification, opt-out, or inquiry.
Non-deletion requests are marked as NOT_APPLICABLE.
"""

import re
from typing import Tuple


class IntentAnalyzer:
    # Explicit retention / keep account active phrases
    NON_DELETION_PHRASES = [
        "leave the account active",
        "keep the account as it is",
        "leave my profile and purchase history in place",
        "leave my profile",
        "continue using the service",
        "keep my account active",
        "keep the account open",
        "do not delete my account",
        "don't delete my account",
        "leave the account open",
    ]

    # Specific requests for correction, export, or access without deletion
    NON_DELETION_PURPOSES = [
        "out of date. please replace it with the new one",
        "download my account information in a portable format",
        "copy of last year's invoices",
        "change the email address used for this account. i want to continue",
        "download my data and keep",
        "export my records and keep",
    ]

    # Multilingual deletion terms
    DELETION_TERMS = [
        r"\bdelet[e|ing|ed|ion]*\b",
        r"\beras[e|ing|ed|ure]*\b",
        r"\bremov[e|ing|ed|al]*\b",
        r"\bclos[e|ing|ed]*\b",
        r"\bsupprim[er|é|ee|ant]*\b",
        r"\bsuppression\b",
        r"\belimin[ar|ado|ando|ación]*\b",
        r"\blösch[en|ung]*\b",
        r"\bexclus[ão|ao|ões]*\b",
        r"\bapagar\b",
        r"\bdeletar\b",
        r"\beffac[er|é]*\b",
        r"\bcancell[are|azione]*\b",
        r"削除",
        r"消去",
        r"삭제",
    ]

    @classmethod
    def is_deletion_authorized(cls, request_text: str) -> Tuple[bool, str]:
        """
        Analyzes request text to determine if it authorizes data deletion.
        Returns:
            (is_authorized, reason)
        """
        if not request_text or not request_text.strip():
            return False, "EMPTY_REQUEST"

        text_lower = request_text.lower().strip()

        # Check for explicit statements demanding account stay active / non-deletion
        for phrase in cls.NON_DELETION_PHRASES:
            if phrase in text_lower:
                return False, f"EXPLICIT_KEEP_ACTIVE: {phrase}"

        for phrase in cls.NON_DELETION_PURPOSES:
            if phrase in text_lower:
                return False, f"NON_DELETION_PURPOSE: {phrase}"

        # If user only requests export, access, update, marketing opt-out without deletion
        has_opt_out = "opt-out" in text_lower or "opt out" in text_lower or "unsubscribe" in text_lower
        has_download = "download" in text_lower or "export" in text_lower or "copy of" in text_lower
        has_update = "update" in text_lower or "change" in text_lower or "replace" in text_lower

        # Check if any deletion term exists
        has_deletion = any(re.search(term, text_lower, re.IGNORECASE) for term in cls.DELETION_TERMS)

        if not has_deletion:
            return False, "NO_DELETION_INTENT_FOUND"

        if (has_opt_out or has_download or has_update) and not has_deletion:
            return False, "NON_DELETION_ACTION"

        return True, "DELETION_AUTHORIZED"
