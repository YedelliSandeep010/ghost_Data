"""
Interactive Live Demonstration of Ghost Data Audit Engine
Demonstrates end-to-end processing for a specific case:
1. Intent analysis
2. Identity graph resolution
3. Multi-modal evidence discovery
4. Policy enforcement
5. Final step generation and verification
"""

import sys
import json
import os
import csv

# Fix Windows console UTF-8 encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, os.path.abspath("code"))

from audit_engine.models import DeletionRequest
from audit_engine.intent_analyzer import IntentAnalyzer
from audit_engine.identity_resolver import IdentityResolver
from audit_engine.activity_indexer import ActivityIndexer
from audit_engine.evidence_indexer import EvidenceIndexer
from audit_engine.policy_engine import PolicyEngine
from audit_engine.audit_orchestrator import AuditOrchestrator

def run_demo(case_id_target="case_36"):
    dataset_dir = os.path.abspath("dataset")
    print("=" * 75)
    print(" 🚀 GHOST DATA AUDIT ENGINE - LIVE STEP-BY-STEP TRACE DEMO")
    print("=" * 75)

    # 1. Resolve Identities
    print("\n[Phase 1] 🔍 Identity Graph Resolution")
    resolver = IdentityResolver()
    identities_csv = os.path.join(dataset_dir, "user_identities.csv")
    audit_csv = os.path.join(dataset_dir, "user_audit_log.csv")
    resolver.load_identities(identities_csv, audit_csv)
    print(f"  -> Successfully resolved {len(resolver.users_by_id)} user profiles across historical logs.")

    # 2. Activity Indexer
    print("\n[Phase 2] ⚡ System Activity Stream Indexing")
    activity_indexer = ActivityIndexer()
    activity_csv = os.path.join(dataset_dir, "system_activity.csv")
    activity_indexer.load_activity(activity_csv)
    print(f"  -> Indexed {len(activity_indexer.activities)} global system operational events.")

    # 3. Evidence Indexing
    print("\n[Phase 3] 🔎 Multi-Modal Evidence Discovery (SQLite, Observability Logs, JSON)")
    evidence_indexer = EvidenceIndexer()
    evidence_indexer.load_and_index(dataset_dir)
    print(f"  -> Indexed {len(evidence_indexer.observations)} grounded evidence observations.")

    # 4. Load Target Request
    requests_path = os.path.join(dataset_dir, "deletion_requests.csv")
    target_req = None
    with open(requests_path, mode="r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["case_id"] == case_id_target:
                target_req = DeletionRequest(
                    case_id=row["case_id"],
                    email=row["email"],
                    requested_at=row["requested_at"],
                    reported_status=row["reported_status"],
                    reported_at=row["reported_at"],
                    audit_at=row["audit_at"],
                    request_text=row["request_text"]
                )
                break

    if not target_req:
        print(f"Case {case_id_target} not found in deletion_requests.csv!")
        return

    print(f"\n[Phase 4] 📥 Incoming Request Inspection: {target_req.case_id}")
    print(f"  • Submitted Email : {target_req.email}")
    print(f"  • Requested At    : {target_req.requested_at}")
    print(f"  • Workflow Claim  : {target_req.reported_status} (reported {target_req.reported_at})")
    print(f"  • Audit Cutoff    : {target_req.audit_at}")
    print(f"  • Request Text    : \"{target_req.request_text}\"")

    # 5. Intent Check
    is_auth, reason = IntentAnalyzer.is_deletion_authorized(target_req.request_text)
    print(f"\n[Phase 5] 🧠 Intent Classification")
    print(f"  • Deletion Authorized: {is_auth}")
    print(f"  • Classifier Reason  : {reason}")

    # 6. Profile Lookup
    profile = resolver.resolve(target_req.email)
    print(f"\n[Phase 6] 👤 User Identity Profile & Aliases")
    if profile:
        print(f"  • Stable User ID  : {profile.user_id}")
        print(f"  • Registered Name : {profile.name}")
        print(f"  • Active Email    : {profile.email}")
        print(f"  • All Known Emails: {list(profile.historical_emails)}")
        print(f"  • All Known Phones: {list(profile.historical_phones)}")
        print(f"  • Associated Hashes: {list(profile.historical_hashes)[:2]}...")
    else:
        print(f"  • Unregistered / External Identity")

    # 7. Orchestrator Audit Execution
    orchestrator = AuditOrchestrator(
        identity_resolver=resolver,
        evidence_indexer=evidence_indexer,
        activity_indexer=activity_indexer,
    )
    result = orchestrator.audit_case(target_req)

    print(f"\n[Phase 7] 📋 Audit Findings, Policy Enforcement & Step Generation")
    print(f"  • Audit Status    : {result.deletion_status}")
    print(f"  • Total Steps     : {len(result.steps)}")
    print(f"\n  Ordered Steps Breakdown:")
    for s in result.steps:
        ev_info = f"(Evidence: {s.evidence_id})" if s.evidence_id else "(Planned Step)"
        print(f"    Step {s.step_no:2d} | [{s.phase:<12}] {s.system_id:<20} {s.resource_id:<18} -> {s.operation:<27} {ev_info}")

    print("\n" + "=" * 75)
    print(f" ✅ CASE {case_id_target} AUDIT COMPLETED SUCCESSFULLY")
    print("=" * 75)

if __name__ == "__main__":
    cid = sys.argv[1] if len(sys.argv) > 1 else "case_36"
    run_demo(cid)
