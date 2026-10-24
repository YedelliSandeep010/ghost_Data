"""
Audit Orchestrator.
Orchestrates the entire deletion audit process for each case:
1. Intent analysis (identifies NOT_APPLICABLE non-deletion requests).
2. Identity graph resolution (current and historical identifiers).
3. Evidence observation and activity log correlation up to audit_at cutoff.
4. Detection of violations, exposed PII, active syncs, and restore risks.
5. Determination of deletion_status: COMPLETE, INCOMPLETE, or NOT_APPLICABLE.
6. Generation and strict ordering of findings, remediation, and verification steps.
"""

from datetime import datetime
from typing import Dict, List, Optional, Set, Any
from .models import AuditStep, CaseResult, DeletionRequest, UserProfile
from .intent_analyzer import IntentAnalyzer
from .identity_resolver import IdentityResolver
from .policy_engine import PolicyEngine
from .evidence_indexer import EvidenceIndexer, EvidenceObservation
from .activity_indexer import ActivityIndexer, SystemActivityItem
from .step_serializer import StepSerializer


class AuditOrchestrator:
    def __init__(
        self,
        identity_resolver: IdentityResolver,
        evidence_indexer: EvidenceIndexer,
        activity_indexer: ActivityIndexer,
    ):
        self.identity_resolver = identity_resolver
        self.evidence_indexer = evidence_indexer
        self.activity_indexer = activity_indexer

    def audit_case(self, request: DeletionRequest) -> CaseResult:
        # Step 1: Verify whether deletion was authorized
        is_authorized, reason = IntentAnalyzer.is_deletion_authorized(request.request_text)
        if not is_authorized:
            return CaseResult(case_id=request.case_id, deletion_status="NOT_APPLICABLE", steps=[])

        # Step 2: Resolve user identity
        profile = self.identity_resolver.resolve(request.email)
        cutoff_time = request.audit_at

        # Step 3: Discover all candidate resources from evidence and activity
        subjects_to_check = {request.email.lower()}
        if profile:
            subjects_to_check.add(profile.user_id.lower())
            for em in profile.historical_emails:
                subjects_to_check.add(em.lower())

        # Collect observations directly mapped to user identity
        user_observations: List[EvidenceObservation] = []
        for subj in subjects_to_check:
            obs_list = self.evidence_indexer.get_observations_for_subject(subj, before_or_at=cutoff_time)
            user_observations.extend(obs_list)

        candidate_resources: Dict[str, str] = {}
        for obs in user_observations:
            candidate_resources[obs.resource_id] = obs.system_id

        # Also find direct activities mentioning user
        if profile:
            direct_act_res = self.activity_indexer.find_resources_for_user(profile, before_or_at=cutoff_time)
            for res_id, sys_id in direct_act_res.items():
                # Verify that resource is not observed belonging to someone else
                obs = self.evidence_indexer.get_latest_observation(res_id, before_or_at=cutoff_time)
                if obs and obs.subject_ref and obs.subject_ref not in subjects_to_check:
                    continue
                candidate_resources[res_id] = sys_id

        # Correlate with deletion_worker activities around reported_at
        # ONLY add if resource is NOT already known belonging to another subject
        try:
            rep_dt = datetime.fromisoformat(request.reported_at.replace("Z", "+00:00"))
            for act in self.activity_indexer.activities:
                if act.source_system == "deletion_worker":
                    act_dt = datetime.fromisoformat(act.event_time.replace("Z", "+00:00"))
                    # Tight window around reported_at (+- 10 minutes)
                    if abs((act_dt - rep_dt).total_seconds()) <= 600:
                        if act.event_time <= cutoff_time:
                            res_id = act.resource_id
                            obs = self.evidence_indexer.get_latest_observation(res_id, before_or_at=cutoff_time)
                            if obs:
                                if obs.subject_ref and obs.subject_ref in subjects_to_check:
                                    candidate_resources[res_id] = obs.system_id
                            else:
                                # If no observation exists, check if details or context match
                                if any(s in act.details.lower() for s in subjects_to_check):
                                    candidate_resources[res_id] = act.target_system
        except Exception:
            pass

        # Step 4: Evaluate ground truth state for each candidate resource
        findings: List[AuditStep] = []
        remediations: List[AuditStep] = []
        verifications: List[AuditStep] = []

        for res_id, sys_id in candidate_resources.items():
            obs = self.evidence_indexer.get_latest_observation(res_id, before_or_at=cutoff_time)
            current_state = obs.state if obs else "UNKNOWN"
            ev_id = obs.file_id if obs else ""

            # Check if this is an active data flow
            if sys_id == "integration_service" or res_id.startswith("data_flow_"):
                if current_state == "ACTIVE":
                    findings.append(AuditStep(0, "FINDING", "integration_service", res_id, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", ev_id))
                    remediations.append(AuditStep(0, "REMEDIATION", "integration_service", res_id, "DISABLE_DATA_FLOW", "DISABLED", ""))
                    verifications.append(AuditStep(0, "VERIFICATION", "integration_service", res_id, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""))
                elif current_state == "DISABLED":
                    verifications.append(AuditStep(0, "VERIFICATION", "integration_service", res_id, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ev_id))

            # Check if this is a backup restore risk
            elif sys_id == "backup_service" or res_id.startswith("backup_"):
                if current_state == "ACTIVE":
                    findings.append(AuditStep(0, "FINDING", "backup_service", res_id, "REPORT_RESTORE_RISK", "ACTIVE", ev_id))
                    remediations.append(AuditStep(0, "REMEDIATION", "backup_service", res_id, "BLOCK_RESTORE", "BLOCKED", ""))
                    verifications.append(AuditStep(0, "VERIFICATION", "backup_service", res_id, "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""))
                elif current_state == "BLOCKED":
                    verifications.append(AuditStep(0, "VERIFICATION", "backup_service", res_id, "VERIFY_RESTORE_BLOCKED", "BLOCKED", ev_id))

            # Check if this is a tombstone
            elif sys_id == "identity_service" or res_id.startswith("tombstone_"):
                if current_state == "PRESENT":
                    # Tombstone exists but exposes PII
                    findings.append(AuditStep(0, "FINDING", "identity_service", res_id, "REPORT_EXPOSED_PII", "PRESENT", ev_id))
                    remediations.append(AuditStep(0, "REMEDIATION", "identity_service", res_id, "REDACT_RECORD", "REDACTED", ""))
                    verifications.append(AuditStep(0, "VERIFICATION", "identity_service", res_id, "VERIFY_RECORD_REDACTED", "REDACTED", ""))
                elif current_state == "REDACTED":
                    verifications.append(AuditStep(0, "VERIFICATION", "identity_service", res_id, "VERIFY_RECORD_REDACTED", "REDACTED", ev_id))

            # Check if this is security audit record
            elif sys_id == "security_service" or res_id.startswith("audit_record_"):
                verifications.append(AuditStep(0, "VERIFICATION", "security_service", res_id, "VERIFY_RECORD_PRESENT", "PRESENT", ev_id))

            # Check if analytics platform
            elif sys_id == "analytics_platform" or res_id.startswith("analytics_"):
                if current_state == "PRESENT":
                    # Check if policy requires ANONYMIZE or DELETE
                    findings.append(AuditStep(0, "FINDING", "analytics_platform", res_id, "REPORT_EXPOSED_PII", "PRESENT", ev_id))
                    remediations.append(AuditStep(0, "REMEDIATION", "analytics_platform", res_id, "ANONYMIZE_RECORD", "ANONYMIZED", ""))
                    verifications.append(AuditStep(0, "VERIFICATION", "analytics_platform", res_id, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", ""))
                elif current_state == "ANONYMIZED":
                    verifications.append(AuditStep(0, "VERIFICATION", "analytics_platform", res_id, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", ev_id))
                elif current_state == "ABSENT":
                    verifications.append(AuditStep(0, "VERIFICATION", "analytics_platform", res_id, "VERIFY_RECORD_ABSENT", "ABSENT", ev_id))

            # Check if support platform
            elif sys_id == "support_platform" or res_id.startswith("support_"):
                if current_state == "PRESENT":
                    action = PolicyEngine.get_required_action(sys_id, res_id)
                    if action == "DELETE":
                        findings.append(AuditStep(0, "FINDING", "support_platform", res_id, "REPORT_REMAINING_RECORD", "PRESENT", ev_id))
                        remediations.append(AuditStep(0, "REMEDIATION", "support_platform", res_id, "DELETE_RECORD", "ABSENT", ""))
                        verifications.append(AuditStep(0, "VERIFICATION", "support_platform", res_id, "VERIFY_RECORD_ABSENT", "ABSENT", ""))
                    else:
                        findings.append(AuditStep(0, "FINDING", "support_platform", res_id, "REPORT_EXPOSED_PII", "PRESENT", ev_id))
                        remediations.append(AuditStep(0, "REMEDIATION", "support_platform", res_id, "REDACT_RECORD", "REDACTED", ""))
                        verifications.append(AuditStep(0, "VERIFICATION", "support_platform", res_id, "VERIFY_RECORD_REDACTED", "REDACTED", ""))
                elif current_state in ("REDACTED", "ABSENT"):
                    op = "VERIFY_RECORD_REDACTED" if current_state == "REDACTED" else "VERIFY_RECORD_ABSENT"
                    verifications.append(AuditStep(0, "VERIFICATION", "support_platform", res_id, op, current_state, ev_id))

            # Other categories: account_service, search_service, export_service
            else:
                if current_state == "PRESENT":
                    findings.append(AuditStep(0, "FINDING", sys_id, res_id, "REPORT_REMAINING_RECORD", "PRESENT", ev_id))
                    remediations.append(AuditStep(0, "REMEDIATION", sys_id, res_id, "DELETE_RECORD", "ABSENT", ""))
                    verifications.append(AuditStep(0, "VERIFICATION", sys_id, res_id, "VERIFY_RECORD_ABSENT", "ABSENT", ""))
                elif current_state == "ABSENT":
                    verifications.append(AuditStep(0, "VERIFICATION", sys_id, res_id, "VERIFY_RECORD_ABSENT", "ABSENT", ev_id))

        # Determine deletion status
        if findings:
            status = "INCOMPLETE"
            # In incomplete cases, proposed remediation and post-remediation verifications have empty evidence_id
            for v in verifications:
                v.evidence_id = ""
            all_steps = findings + remediations + verifications
        else:
            status = "COMPLETE"
            # In complete cases, include ONLY verification steps citing valid evidence
            all_steps = [v for v in verifications if v.evidence_id]

        # Deduplicate steps by (phase, system_id, resource_id, operation)
        unique_steps: List[AuditStep] = []
        seen = set()
        for s in all_steps:
            key = (s.phase, s.system_id, s.resource_id, s.operation)
            if key not in seen:
                seen.add(key)
                unique_steps.append(s)

        sorted_steps = StepSerializer.sort_and_number_steps(unique_steps)
        return CaseResult(case_id=request.case_id, deletion_status=status, steps=sorted_steps)
