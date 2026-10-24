"""
Ghost Data Deletion Audit Agent - Main Application Entry Point.
Executes end-to-end deletion auditing, generates compliant output.csv, and runs evaluation.
"""

import argparse
import csv
import os
import sys
import time
from typing import List, Dict

# Ensure audit_engine is in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from audit_engine.models import DeletionRequest, CaseResult
from audit_engine.identity_resolver import IdentityResolver
from audit_engine.evidence_indexer import EvidenceIndexer
from audit_engine.activity_indexer import ActivityIndexer
from audit_engine.audit_orchestrator import AuditOrchestrator
from audit_engine.step_serializer import StepSerializer
from evaluation.evaluator import DeletionEvaluator


def parse_args():
    parser = argparse.ArgumentParser(description="Ghost Data Deletion Audit Agent")
    parser.add_argument(
        "--dataset-dir",
        type=str,
        default=os.path.join(os.path.dirname(CURRENT_DIR), "hackerrank-orchestrate-october26-main", "dataset"),
        help="Path to dataset directory containing CSVs and evidence",
    )
    parser.add_argument(
        "--requests",
        type=str,
        default="deletion_requests.csv",
        help="Name of requests CSV to audit (e.g. deletion_requests.csv or sample_deletion_requests.csv)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="output.csv",
        help="Output CSV path for audited predictions",
    )
    parser.add_argument(
        "--evaluate",
        type=str,
        default=None,
        help="Optional path to canonical ground-truth CSV to evaluate predictions against",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of cases to process",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    start_time = time.time()

    dataset_dir = os.path.abspath(args.dataset_dir)
    print(f"============================================================")
    print(f"[*] Ghost Data Deletion Audit Agent")
    print(f"[*] Dataset directory: {dataset_dir}")
    print(f"============================================================")

    if not os.path.exists(dataset_dir):
        print(f"[!] Error: Dataset directory not found at: {dataset_dir}")
        sys.exit(1)

    # 1. Initialize Components
    print("[1/4] Loading and resolving identities...")
    resolver = IdentityResolver()
    identities_csv = os.path.join(dataset_dir, "user_identities.csv")
    audit_csv = os.path.join(dataset_dir, "user_audit_log.csv")
    resolver.load_identities(identities_csv, audit_csv)
    print(f"      -> Resolved {len(resolver.users_by_id)} user identity profiles.")

    print("[2/4] Indexing system activity log...")
    activity_indexer = ActivityIndexer()
    activity_csv = os.path.join(dataset_dir, "system_activity.csv")
    activity_indexer.load_activity(activity_csv)
    print(f"      -> Indexed {len(activity_indexer.activities)} system operational events.")

    print("[3/4] Indexing multi-modal evidence repository...")
    evidence_indexer = EvidenceIndexer()
    evidence_indexer.load_and_index(dataset_dir)
    print(f"      -> Indexed {len(evidence_indexer.observations)} grounded evidence observations.")

    orchestrator = AuditOrchestrator(
        identity_resolver=resolver,
        evidence_indexer=evidence_indexer,
        activity_indexer=activity_indexer,
    )

    # 2. Ingest Requests
    requests_path = os.path.join(dataset_dir, args.requests) if not os.path.isabs(args.requests) else args.requests
    if not os.path.exists(requests_path):
        # Check relative to cwd
        if os.path.exists(args.requests):
            requests_path = os.path.abspath(args.requests)
        else:
            print(f"[!] Error: Requests file not found at: {requests_path}")
            sys.exit(1)

    print(f"[4/4] Auditing requests from: {os.path.basename(requests_path)}...")
    with open(requests_path, mode="r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))

    if args.limit:
        reader = reader[:args.limit]

    results: List[CaseResult] = []
    output_rows: List[Dict[str, str]] = []

    for idx, row in enumerate(reader, start=1):
        req = DeletionRequest(
            case_id=row["case_id"].strip(),
            email=row["email"].strip(),
            requested_at=row["requested_at"].strip(),
            reported_status=row["reported_status"].strip(),
            reported_at=row["reported_at"].strip(),
            audit_at=row["audit_at"].strip(),
            request_text=row["request_text"].strip(),
        )

        res = orchestrator.audit_case(req)
        results.append(res)

        serialized_json = StepSerializer.serialize_to_json(res.steps)
        output_rows.append({
            "case_id": res.case_id,
            "deletion_status": res.deletion_status,
            "steps_json": serialized_json,
        })

        if args.verbose or (idx % 50 == 0) or (idx == len(reader)):
            print(f"      Processed [{idx}/{len(reader)}] {req.case_id} -> {res.deletion_status} ({len(res.steps)} steps)")

    def case_sort_key(item):
        cid = item.get("case_id", "")
        parts = cid.split("_")
        if len(parts) == 2 and parts[1].isdigit():
            return (0, int(parts[1]))
        return (1, cid)

    # 3. Sort output rows by case_id (natural ordering)
    output_rows.sort(key=case_sort_key)

    # 4. Write to output.csv
    out_path = os.path.abspath(args.output)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        for r in output_rows:
            writer.writerow([r["case_id"], r["deletion_status"], r["steps_json"]])

    elapsed = time.time() - start_time
    print(f"[*] Successfully generated {len(output_rows)} audit rows in {elapsed:.2f}s.")
    print(f"[*] Predictions saved to: {out_path}")

    # 5. Optional Evaluation
    if args.evaluate:
        eval_path = os.path.abspath(args.evaluate)
        if not os.path.exists(eval_path):
            eval_path = os.path.join(dataset_dir, args.evaluate)

        if os.path.exists(eval_path):
            print(f"\n============================================================")
            print(f"[*] Evaluation Against: {os.path.basename(eval_path)}")
            print(f"============================================================")
            with open(eval_path, mode="r", encoding="utf-8") as f:
                gt_rows = list(csv.DictReader(f))

            metrics = DeletionEvaluator.evaluate(gt_rows, output_rows)
            print(f"  Cases Evaluated:      {metrics['total_cases']}")
            print(f"  Status Accuracy:      {metrics['status_accuracy']:.2f}%")
            print(f"  Exact Sequence Acc:   {metrics['sequence_accuracy']:.2f}%")
            print(f"  Step Precision:       {metrics['step_precision']:.2f}%")
            print(f"  Step Recall:          {metrics['step_recall']:.2f}%")
            print(f"  Step F1 Score:        {metrics['step_f1']:.2f}%")
            print(f"\n  Field-level Accuracies:")
            for field, acc in metrics["field_accuracy"].items():
                print(f"    - {field:<16}: {acc:.2f}%")
            print(f"\n  Status Confusion Matrix:")
            print(f"    {'True / Pred':<16} {'COMPLETE':<12} {'INCOMPLETE':<12} {'NOT_APPLICABLE':<14}")
            for true_s, preds in metrics["confusion_matrix"].items():
                print(f"    {true_s:<16} {preds['COMPLETE']:<12} {preds['INCOMPLETE']:<12} {preds['NOT_APPLICABLE']:<14}")
        else:
            print(f"[!] Evaluation file not found: {eval_path}")


if __name__ == "__main__":
    main()
