"""
Evidence Indexer.
Extracts grounded point-in-time observations across all evidence file types:
- SQLite-compatible SQL database snapshots executed in-memory (.sql)
- Structured service logs with trace_id correlation (.log)
- Records assurance and handover snapshots (.txt, .json)
"""

import csv
import json
import os
import re
import sqlite3
from typing import Dict, List, Optional, Set, Tuple


class EvidenceObservation:
    def __init__(self, file_id: str, captured_at: str, system_id: str, resource_id: str, state: str, subject_ref: Optional[str] = None):
        self.file_id = file_id
        self.captured_at = captured_at
        self.system_id = system_id
        self.resource_id = resource_id
        self.state = state  # ABSENT, PRESENT, REDACTED, ANONYMIZED, ACTIVE, BLOCKED, DISABLED
        self.subject_ref = subject_ref.lower().strip() if subject_ref else None

    def __repr__(self):
        return f"<Observation {self.file_id} {self.system_id}:{self.resource_id} -> {self.state} ({self.subject_ref})>"


class EvidenceIndexer:
    def __init__(self):
        self.evidence_meta: Dict[str, Dict[str, str]] = {}
        self.observations: List[EvidenceObservation] = []
        self.by_resource: Dict[str, List[EvidenceObservation]] = {}
        self.by_subject: Dict[str, List[EvidenceObservation]] = {}

    def load_and_index(self, dataset_dir: str):
        """Loads evidence manifest and indexes all evidence files."""
        manifest_path = os.path.join(dataset_dir, "evidence_files.csv")
        with open(manifest_path, mode="r", encoding="utf-8") as f:
            self.evidence_meta = {r["file_id"]: r for r in csv.DictReader(f)}

        for fid, meta in self.evidence_meta.items():
            rel_path = meta["file_path"].replace("/", os.sep)
            full_path = os.path.join(dataset_dir, rel_path)
            if not os.path.exists(full_path):
                continue
            ext = os.path.splitext(full_path)[1].lower()
            captured_at = meta["captured_at"]

            if ext == ".sql":
                self._parse_sql_sqlite(fid, captured_at, full_path)
            elif ext == ".log":
                self._parse_log_correlated(fid, captured_at, full_path)
            elif ext == ".json":
                self._parse_json(fid, captured_at, full_path)
            elif ext == ".txt":
                self._parse_txt(fid, captured_at, full_path)

    def _add_obs(self, obs: EvidenceObservation):
        self.observations.append(obs)
        self.by_resource.setdefault(obs.resource_id, []).append(obs)
        if obs.subject_ref:
            self.by_subject.setdefault(obs.subject_ref, []).append(obs)

    def _parse_sql_sqlite(self, fid: str, captured_at: str, path: str):
        """Executes SQL script into an in-memory SQLite database and extracts observations."""
        try:
            conn = sqlite3.connect(":memory:")
            conn.row_factory = sqlite3.Row
            with open(path, mode="r", encoding="utf-8", errors="ignore") as f:
                conn.executescript(f.read())

            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]

            for tbl in tables:
                if tbl in ("snapshot_scope",):
                    continue
                rows = conn.execute(f"SELECT * FROM {tbl}").fetchall()
                for r in rows:
                    keys = r.keys()
                    res_id = r["resource_id"] if "resource_id" in keys else None
                    if not res_id:
                        continue

                    # Subject reference: user_id, email, customer_reference, subject_reference
                    subj = None
                    for sk in ["customer_reference", "subject_reference", "user_id", "email", "owner_email", "requester_email", "customer_email"]:
                        if sk in keys and r[sk]:
                            subj = str(r[sk])
                            break

                    # Map table to system_id and state
                    sys_id = "unknown"
                    state = "PRESENT"

                    if tbl == "customer_profiles" or "profiles" in tbl:
                        sys_id = "account_service"
                        state = "PRESENT"
                    elif tbl == "customer_search_documents" or "search" in tbl:
                        sys_id = "search_service"
                        state = "PRESENT"
                    elif tbl == "customer_analytics_profiles" or "analytics" in tbl:
                        sys_id = "analytics_platform"
                        has_pii = any(r[k] for k in ["email", "phone", "email_hash", "customer_reference"] if k in keys)
                        state = "PRESENT" if has_pii else "ANONYMIZED"
                    elif tbl == "support_records" or "support" in tbl:
                        sys_id = "support_platform"
                        has_pii = bool(r["requester_email"]) if "requester_email" in keys else True
                        state = "PRESENT" if has_pii else "REDACTED"
                    elif tbl == "customer_exports" or "export" in tbl:
                        sys_id = "export_service"
                        state = "PRESENT"
                    elif tbl == "connector_subscriptions" or "connector" in tbl:
                        sys_id = "integration_service"
                        enabled = r["enabled"] if "enabled" in keys else 1
                        state = "ACTIVE" if enabled else "DISABLED"
                    elif tbl == "backup_restore_entries" or "backup" in tbl:
                        sys_id = "backup_service"
                        allowed = r["restore_allowed"] if "restore_allowed" in keys else 1
                        state = "ACTIVE" if allowed else "BLOCKED"
                    elif tbl == "security_audit_records" or "security" in tbl or "audit" in tbl:
                        sys_id = "security_service"
                        state = "PRESENT"

                    self._add_obs(EvidenceObservation(fid, captured_at, sys_id, res_id, state, subj))

            conn.close()
        except Exception:
            # Fallback to regex if SQLite execution fails on dialect quirk
            self._parse_sql_regex(fid, captured_at, path)

    def _parse_sql_regex(self, fid: str, captured_at: str, path: str):
        with open(path, mode="r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        inserts = re.findall(r"INSERT\s+INTO\s+[\"']?([A-Za-z0-9_]+)[\"']?\s+VALUES\s*\((.*?)\);", content, re.IGNORECASE)
        for tbl, val_str in inserts:
            vals = [v.strip().strip("'\"") for v in val_str.split(",")]
            res_id = vals[0]
            subj = None
            if len(vals) > 1 and vals[1] != "NULL":
                subj = vals[1]
            if len(vals) > 3 and "@" in vals[3]:
                subj = vals[3]

            sys_id = "account_service"
            if res_id.startswith("search_"): sys_id = "search_service"
            elif res_id.startswith("support_"): sys_id = "support_platform"
            elif res_id.startswith("backup_"): sys_id = "backup_service"
            elif res_id.startswith("data_flow_"): sys_id = "integration_service"
            self._add_obs(EvidenceObservation(fid, captured_at, sys_id, res_id, "PRESENT", subj))

    def _parse_log_correlated(self, fid: str, captured_at: str, path: str):
        """Parses logs with trace_id correlation across queries and responses."""
        traces: Dict[str, str] = {}
        with open(path, mode="r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue

                # 1. JSON Lines
                if "{" in line_str and "}" in line_str:
                    try:
                        idx = line_str.find("{")
                        d = json.loads(line_str[idx:])
                        tid = d.get("trace_id")
                        subj = d.get("subject_ref") or d.get("lookup_key") or d.get("correlation_key") or d.get("customer_reference")
                        if tid and subj and subj != "null":
                            traces[tid] = subj

                        res_id = d.get("resource_id")
                        if res_id:
                            sys_id = d.get("service") or d.get("logger") or "unknown"
                            owner = d.get("subject_ref") or d.get("customer_reference") or (traces.get(tid) if tid else None)

                            state = "PRESENT"
                            http_status = str(d.get("http_status", ""))
                            rows = str(d.get("rows", ""))
                            if http_status == "404" or rows == "0":
                                state = "ABSENT"
                            elif d.get("enabled") is True or d.get("restore_allowed") is True:
                                state = "ACTIVE"
                            elif d.get("enabled") is False:
                                state = "DISABLED"
                            elif d.get("restore_allowed") is False:
                                state = "BLOCKED"
                            elif d.get("email") is None and sys_id == "analytics_platform":
                                state = "ANONYMIZED"

                            self._add_obs(EvidenceObservation(fid, captured_at, sys_id, res_id, state, owner))
                        continue
                    except Exception:
                        pass

                # 2. Key-Value Lines
                tid_match = re.search(r"trace_id=([^\s]+)", line_str)
                tid = tid_match.group(1) if tid_match else None

                key_match = re.search(r"lookup_key=([^\s]+)", line_str)
                if tid and key_match:
                    k = key_match.group(1)
                    if k != "null":
                        traces[tid] = k

                res_match = re.search(r"resource_id=([a-zA-Z0-9_]+)", line_str)
                if res_match:
                    res_id = res_match.group(1)
                    sys_match = re.search(r"service=([a-zA-Z0-9_]+)", line_str)
                    sys_id = sys_match.group(1) if sys_match else "unknown"

                    owner = traces.get(tid) if tid else None
                    state = "PRESENT"
                    if "http_status=404" in line_str or "rows=0" in line_str:
                        state = "ABSENT"
                    elif "enabled=true" in line_str or "restore_allowed=true" in line_str:
                        state = "ACTIVE"
                    elif "enabled=false" in line_str:
                        state = "DISABLED"
                    elif "restore_allowed=false" in line_str:
                        state = "BLOCKED"
                    elif "email=null" in line_str and "analytics" in sys_id:
                        state = "ANONYMIZED"
                    elif "requester_email=null" in line_str and "support" in sys_id:
                        state = "REDACTED"
                    elif "http_status=200" in line_str or "result=hit" in line_str or "rows=1" in line_str:
                        state = "PRESENT"

                    self._add_obs(EvidenceObservation(fid, captured_at, sys_id, res_id, state, owner))

    def _parse_txt(self, fid: str, captured_at: str, path: str):
        with open(path, mode="r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.startswith("- "):
                    parts = [p.strip() for p in line[2:].split("|")]
                    if len(parts) >= 6:
                        sys_id = parts[1]
                        res_id = parts[2]
                        status = parts[4]
                        subject = parts[5]
                        state = "UNKNOWN"
                        if status == "NOT_FOUND":
                            state = "ABSENT"
                        elif status in ("FOUND", "IDENTIFIABLE"):
                            state = "PRESENT"
                        elif status == "ANONYMIZED":
                            state = "ANONYMIZED"
                        elif status == "REDACTED":
                            state = "REDACTED"
                        elif status == "ACTIVE":
                            state = "ACTIVE"
                        elif status in ("BLOCKED", "DISABLED"):
                            state = status
                        self._add_obs(EvidenceObservation(fid, captured_at, sys_id, res_id, state, subject))

    def _parse_json(self, fid: str, captured_at: str, path: str):
        with open(path, mode="r", encoding="utf-8", errors="ignore") as f:
            try:
                data = json.load(f)
            except Exception:
                return

        # Snapshot bundle format
        if "snapshots" in data:
            for snap in data["snapshots"]:
                records = snap.get("records", [])
                for rec in records:
                    res_id = rec.get("resource_id", "")
                    subj = rec.get("subject_reference", "")
                    if res_id.startswith("tombstone_"):
                        has_pii = any(rec.get(k) for k in ["name", "email", "phone", "email_hash"])
                        state = "PRESENT" if has_pii else "REDACTED"
                        self._add_obs(EvidenceObservation(fid, captured_at, "identity_service", res_id, state, subj))
                    elif res_id.startswith("audit_record_"):
                        self._add_obs(EvidenceObservation(fid, captured_at, "security_service", res_id, "PRESENT", subj))
                    elif res_id.startswith("account_"):
                        self._add_obs(EvidenceObservation(fid, captured_at, "account_service", res_id, "PRESENT", subj))

        # Service exports format
        if "service_exports" in data:
            exports = data["service_exports"]
            if "account_service" in exports:
                for item in exports["account_service"].get("profile_lookups", []):
                    res_id = item.get("resource_id")
                    status_code = item.get("status_code")
                    state = "ABSENT" if status_code == 404 else "PRESENT"
                    prof = item.get("profile") or {}
                    subj = prof.get("email") or prof.get("customer_reference")
                    self._add_obs(EvidenceObservation(fid, captured_at, "account_service", res_id, state, subj))

            if "analytics_platform" in exports:
                for item in exports["analytics_platform"].get("profiles", []):
                    res_id = item.get("resource_id")
                    has_pii = any(item.get(k) for k in ["email", "phone", "email_hash", "customer_reference"])
                    state = "PRESENT" if has_pii else "ANONYMIZED"
                    subj = item.get("email") or item.get("customer_reference")
                    self._add_obs(EvidenceObservation(fid, captured_at, "analytics_platform", res_id, state, subj))

            if "search_service" in exports:
                for item in exports["search_service"].get("index_queries", []):
                    res_id = item.get("resource_id")
                    hits = item.get("hits", {})
                    total_hits = hits.get("total", 0)
                    state = "PRESENT" if total_hits > 0 else "ABSENT"
                    subj = item.get("query")
                    if hits.get("documents"):
                        doc = hits["documents"][0]
                        subj = doc.get("email") or subj
                    self._add_obs(EvidenceObservation(fid, captured_at, "search_service", res_id, state, subj))

                for item in exports["search_service"].get("index_entries", []):
                    res_id = item.get("resource_id")
                    status = item.get("status", "")
                    state = "PRESENT" if status in ("hit", "found") else "ABSENT"
                    subj = item.get("email") or item.get("customer_reference")
                    self._add_obs(EvidenceObservation(fid, captured_at, "search_service", res_id, state, subj))

            if "integration_service" in exports:
                for item in exports["integration_service"].get("connectors", []):
                    res_id = item.get("resource_id")
                    enabled = item.get("enabled", False)
                    state = "ACTIVE" if enabled else "DISABLED"
                    subj = item.get("customer_email") or item.get("customer_reference")
                    self._add_obs(EvidenceObservation(fid, captured_at, "integration_service", res_id, state, subj))

            if "backup_service" in exports:
                for item in exports["backup_service"].get("restore_entries", []):
                    res_id = item.get("resource_id")
                    allowed = item.get("restore_allowed", False)
                    state = "ACTIVE" if allowed else "BLOCKED"
                    subj = item.get("customer_reference") or item.get("customer_email")
                    self._add_obs(EvidenceObservation(fid, captured_at, "backup_service", res_id, state, subj))

            if "export_service" in exports:
                for item in exports["export_service"].get("exports", []):
                    res_id = item.get("resource_id")
                    subj = item.get("owner_email") or item.get("customer_reference")
                    self._add_obs(EvidenceObservation(fid, captured_at, "export_service", res_id, "PRESENT", subj))

            if "security_service" in exports:
                for item in exports["security_service"].get("audit_records", []):
                    res_id = item.get("resource_id")
                    subj = item.get("subject_reference")
                    self._add_obs(EvidenceObservation(fid, captured_at, "security_service", res_id, "PRESENT", subj))

            if "support_platform" in exports:
                for item in exports["support_platform"].get("tickets", []):
                    res_id = item.get("resource_id")
                    has_pii = bool(item.get("requester_email"))
                    state = "PRESENT" if has_pii else "REDACTED"
                    subj = item.get("requester_email") or item.get("customer_reference")
                    self._add_obs(EvidenceObservation(fid, captured_at, "support_platform", res_id, state, subj))

        # Direct records list format
        if "records" in data and isinstance(data["records"], list):
            for rec in data["records"]:
                res_id = rec.get("resource_id")
                if not res_id:
                    continue
                subj = rec.get("subject_reference") or rec.get("owner_email") or rec.get("email") or rec.get("user_id")
                sys_id = "unknown"
                if res_id.startswith("account_"): sys_id = "account_service"
                elif res_id.startswith("search_"): sys_id = "search_service"
                elif res_id.startswith("support_"): sys_id = "support_platform"
                elif res_id.startswith("analytics_"): sys_id = "analytics_platform"
                elif res_id.startswith("data_flow_"): sys_id = "integration_service"
                elif res_id.startswith("backup_"): sys_id = "backup_service"
                elif res_id.startswith("export_"): sys_id = "export_service"
                elif res_id.startswith("tombstone_"): sys_id = "identity_service"
                elif res_id.startswith("audit_record_"): sys_id = "security_service"

                state = "PRESENT"
                if "result" in rec:
                    r = rec["result"]
                    if r == "NOT_FOUND": state = "ABSENT"
                    elif r == "ANONYMIZED": state = "ANONYMIZED"
                    elif r == "REDACTED": state = "REDACTED"
                elif "download_available" in rec:
                    state = "PRESENT" if rec["download_available"] else "ABSENT"
                elif "reporting_window" in rec:
                    has_pii = any(rec.get(k) for k in ["email", "phone", "user_id", "email_hash"])
                    state = "PRESENT" if has_pii else "ANONYMIZED"

                self._add_obs(EvidenceObservation(fid, captured_at, sys_id, res_id, state, subj))

    def get_latest_observation(self, resource_id: str, before_or_at: Optional[str] = None) -> Optional[EvidenceObservation]:
        candidates = self.by_resource.get(resource_id, [])
        if before_or_at:
            candidates = [c for c in candidates if c.captured_at <= before_or_at]
        if not candidates:
            return None
        candidates.sort(key=lambda x: x.captured_at, reverse=True)
        return candidates[0]

    def get_observations_for_subject(self, subject: str, before_or_at: Optional[str] = None) -> List[EvidenceObservation]:
        candidates = self.by_subject.get(subject.lower(), [])
        if before_or_at:
            candidates = [c for c in candidates if c.captured_at <= before_or_at]
        return candidates
