"""
Evaluator for Ghost Data Deletion Audit Agent.
Evaluates predictions against ground truth canonical answers:
- Case-level deletion-status accuracy
- Step-level precision, recall, and F1
- Field-level accuracy (system_id, resource_id, operation, state, evidence_id)
- Sequence accuracy
- Status confusion matrix
"""

import json
from typing import Dict, List, Any, Tuple


class DeletionEvaluator:
    @staticmethod
    def evaluate(ground_truth_rows: List[Dict[str, str]], predicted_rows: List[Dict[str, str]]) -> Dict[str, Any]:
        gt_by_case = {r["case_id"]: r for r in ground_truth_rows}
        pred_by_case = {r["case_id"]: r for r in predicted_rows}

        total_cases = len(gt_by_case)
        correct_status_count = 0
        exact_sequence_matches = 0

        total_gt_steps = 0
        total_pred_steps = 0
        matched_steps = 0

        # Field-level matches
        field_matches = {
            "phase": 0,
            "system_id": 0,
            "resource_id": 0,
            "operation": 0,
            "state": 0,
            "evidence_id": 0,
        }
        total_fields_evaluated = 0

        # Confusion matrix
        confusion_matrix = {
            "COMPLETE": {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0},
            "INCOMPLETE": {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0},
            "NOT_APPLICABLE": {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0},
        }

        case_reports = []

        for cid, gt_row in gt_by_case.items():
            pred_row = pred_by_case.get(cid)
            if not pred_row:
                continue

            gt_status = gt_row["deletion_status"].strip()
            pred_status = pred_row["deletion_status"].strip()

            if gt_status in confusion_matrix and pred_status in confusion_matrix[gt_status]:
                confusion_matrix[gt_status][pred_status] += 1

            status_correct = (gt_status == pred_status)
            if status_correct:
                correct_status_count += 1

            # Parse steps
            try:
                gt_steps = json.loads(gt_row["steps_json"])
            except Exception:
                gt_steps = []

            try:
                pred_steps = json.loads(pred_row["steps_json"])
            except Exception:
                pred_steps = []

            total_gt_steps += len(gt_steps)
            total_pred_steps += len(pred_steps)

            # Check exact sequence match
            is_exact = (status_correct and len(gt_steps) == len(pred_steps))
            if is_exact:
                for s_gt, s_pred in zip(gt_steps, pred_steps):
                    for k in ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]:
                        if str(s_gt.get(k, "")).strip() != str(s_pred.get(k, "")).strip():
                            is_exact = False
                            break
                    if not is_exact:
                        break

            if is_exact:
                exact_sequence_matches += 1

            # Step and field matching
            # Match steps by (phase, system_id, resource_id, operation)
            gt_step_keys = [(s.get("phase"), s.get("system_id"), s.get("resource_id"), s.get("operation")) for s in gt_steps]
            pred_step_keys = [(s.get("phase"), s.get("system_id"), s.get("resource_id"), s.get("operation")) for s in pred_steps]

            step_overlap = 0
            for skey in pred_step_keys:
                if skey in gt_step_keys:
                    step_overlap += 1
            matched_steps += step_overlap

            # Compare field alignments
            for s_gt, s_pred in zip(gt_steps, pred_steps):
                total_fields_evaluated += 6
                for k in ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]:
                    if str(s_gt.get(k, "")).strip() == str(s_pred.get(k, "")).strip():
                        field_matches[k] += 1

            case_reports.append({
                "case_id": cid,
                "gt_status": gt_status,
                "pred_status": pred_status,
                "status_correct": status_correct,
                "exact_sequence": is_exact,
                "gt_steps_count": len(gt_steps),
                "pred_steps_count": len(pred_steps),
            })

        status_accuracy = (correct_status_count / total_cases * 100) if total_cases > 0 else 0
        sequence_accuracy = (exact_sequence_matches / total_cases * 100) if total_cases > 0 else 0
        precision = (matched_steps / total_pred_steps * 100) if total_pred_steps > 0 else 0
        recall = (matched_steps / total_gt_steps * 100) if total_gt_steps > 0 else 0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0

        field_acc = {}
        pair_count = min(total_gt_steps, total_pred_steps)
        for k, v in field_matches.items():
            field_acc[k] = (v / pair_count * 100) if pair_count > 0 else 0

        return {
            "total_cases": total_cases,
            "status_accuracy": status_accuracy,
            "sequence_accuracy": sequence_accuracy,
            "step_precision": precision,
            "step_recall": recall,
            "step_f1": f1,
            "field_accuracy": field_acc,
            "confusion_matrix": confusion_matrix,
            "case_reports": case_reports,
        }
