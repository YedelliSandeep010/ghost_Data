"""
Activity Indexer.
Parses system_activity.csv and indexes operations, system events, and resource links.
Allows fast lookup of activity by user_id, email, resource_id, and timestamp.
"""

import csv
import re
from typing import Dict, List, Optional, Set, Any
from .models import UserProfile


class SystemActivityItem:
    def __init__(self, raw: Dict[str, str]):
        self.activity_id = raw["activity_id"].strip()
        self.event_time = raw["event_time"].strip()
        self.event_type = raw["event_type"].strip()
        self.source_system = raw["source_system"].strip()
        self.target_system = raw["target_system"].strip()
        self.resource_id = raw["resource_id"].strip()
        self.reported_result = raw["reported_result"].strip()
        self.details = raw["details"].strip()


class ActivityIndexer:
    def __init__(self):
        self.activities: List[SystemActivityItem] = []
        self.by_resource: Dict[str, List[SystemActivityItem]] = {}
        self.by_user_ref: Dict[str, List[SystemActivityItem]] = {}

    def load_activity(self, activity_csv_path: str):
        """Loads and indexes all system activities."""
        with open(activity_csv_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                item = SystemActivityItem(row)
                self.activities.append(item)

                res = item.resource_id
                if res:
                    self.by_resource.setdefault(res, []).append(item)

                # Extract user references or emails from details if any
                details = item.details
                user_matches = re.findall(r"\buser_\d+\b", details)
                for u in user_matches:
                    self.by_user_ref.setdefault(u, []).append(item)

                email_matches = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", details)
                for em in email_matches:
                    self.by_user_ref.setdefault(em.lower(), []).append(item)

    def get_activities_for_resource(self, resource_id: str, before_or_at: Optional[str] = None) -> List[SystemActivityItem]:
        """Gets all activities for a resource up to the cutoff timestamp."""
        items = self.by_resource.get(resource_id, [])
        if before_or_at:
            items = [it for it in items if it.event_time <= before_or_at]
        return items

    def find_resources_for_user(self, profile: UserProfile, before_or_at: Optional[str] = None) -> Dict[str, str]:
        """
        Discovers all resources tied to a user by inspecting user references and activities.
        Returns a dict mapping: resource_id -> target_system.
        """
        resources: Dict[str, str] = {}

        # 1. Check direct user references in activity details
        check_keys = {profile.user_id}
        for em in profile.historical_emails:
            check_keys.add(em.lower())

        for k in check_keys:
            for it in self.by_user_ref.get(k, []):
                if before_or_at and it.event_time > before_or_at:
                    continue
                if it.resource_id:
                    resources[it.resource_id] = it.target_system

        return resources
