"""
Identity Resolver.
Resolves current and historical user identities, tracking email changes, phone changes,
name variations, and email hashes from user_identities.csv and user_audit_log.csv.
"""

import csv
import os
from typing import Dict, Optional, Set
from .models import UserProfile


class IdentityResolver:
    def __init__(self):
        self.users_by_id: Dict[str, UserProfile] = {}
        self.email_to_userid: Dict[str, str] = {}
        self.phone_to_userid: Dict[str, str] = {}
        self.hash_to_userid: Dict[str, str] = {}
        self.name_to_userid: Dict[str, str] = {}

    def load_identities(self, identities_csv_path: str, audit_log_csv_path: str):
        """Loads user snapshots and applies audit log to reconstruct complete identity graph."""
        # 1. Load current identities
        with open(identities_csv_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"].strip()
                name = row["name"].strip()
                email = row["email"].strip()
                phone = row["phone"].strip()
                email_hash = row["email_hash"].strip()
                updated_at = row["updated_at"].strip()

                profile = UserProfile(
                    user_id=uid,
                    name=name,
                    email=email,
                    phone=phone,
                    email_hash=email_hash,
                    updated_at=updated_at,
                )
                profile.historical_emails.add(email.lower())
                profile.historical_phones.add(phone)
                profile.historical_names.add(name.lower())
                profile.historical_hashes.add(email_hash)

                self.users_by_id[uid] = profile
                self.email_to_userid[email.lower()] = uid
                self.phone_to_userid[phone] = uid
                self.hash_to_userid[email_hash] = uid
                self.name_to_userid[name.lower()] = uid

        # 2. Ingest audit logs to find historical aliases
        if os.path.exists(audit_log_csv_path):
            with open(audit_log_csv_path, mode="r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    uid = row["user_id"].strip()
                    field = row["field_name"].strip()
                    old_val = row["old_value"].strip()
                    new_val = row["new_value"].strip()

                    profile = self.users_by_id.get(uid)
                    if not profile:
                        continue

                    if field == "email":
                        if old_val:
                            profile.historical_emails.add(old_val.lower())
                            self.email_to_userid[old_val.lower()] = uid
                        if new_val:
                            profile.historical_emails.add(new_val.lower())
                            self.email_to_userid[new_val.lower()] = uid
                    elif field == "phone":
                        if old_val:
                            profile.historical_phones.add(old_val)
                            self.phone_to_userid[old_val] = uid
                        if new_val:
                            profile.historical_phones.add(new_val)
                            self.phone_to_userid[new_val] = uid
                    elif field == "name":
                        if old_val:
                            profile.historical_names.add(old_val.lower())
                            self.name_to_userid[old_val.lower()] = uid
                        if new_val:
                            profile.historical_names.add(new_val.lower())
                            self.name_to_userid[new_val.lower()] = uid
                    elif field == "email_hash":
                        if old_val:
                            profile.historical_hashes.add(old_val)
                            self.hash_to_userid[old_val] = uid
                        if new_val:
                            profile.historical_hashes.add(new_val)
                            self.hash_to_userid[new_val] = uid

    def resolve(self, query: str) -> Optional[UserProfile]:
        """Resolves a user profile by email, phone, user_id, hash, or name."""
        if not query:
            return None
        q = query.strip()
        q_lower = q.lower()

        # Check by direct user_id
        if q in self.users_by_id:
            return self.users_by_id[q]

        # Check by email
        if q_lower in self.email_to_userid:
            return self.users_by_id[self.email_to_userid[q_lower]]

        # Check by phone
        if q in self.phone_to_userid:
            return self.users_by_id[self.phone_to_userid[q]]

        # Check by hash
        if q in self.hash_to_userid:
            return self.users_by_id[self.hash_to_userid[q]]

        # Check by name
        if q_lower in self.name_to_userid:
            return self.users_by_id[self.name_to_userid[q_lower]]

        return None
