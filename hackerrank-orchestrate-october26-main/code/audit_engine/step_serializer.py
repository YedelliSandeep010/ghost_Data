"""
Step Serializer.
Applies the strict sorting contract for audit steps:
1. Phase order: FINDING -> REMEDIATION -> VERIFICATION
2. Operation order defined by problem specification table
3. system_id ascending
4. resource_id ascending
Assigns consecutive step_no starting at 1.
Serializes steps into standard JSON array string.
"""

import json
from typing import List, Dict, Any
from .models import AuditStep, PHASE_PRIORITY, OPERATION_PRIORITY


class StepSerializer:
    @classmethod
    def sort_and_number_steps(cls, steps: List[AuditStep]) -> List[AuditStep]:
        """
        Sorts steps strictly according to phase, operation priority, system_id, and resource_id.
        Re-numbers step_no consecutively starting at 1.
        """
        def sort_key(s: AuditStep):
            phase_val = PHASE_PRIORITY.get(s.phase, 99)
            op_val = OPERATION_PRIORITY.get(s.operation, 99)
            return (phase_val, op_val, s.system_id, s.resource_id)

        sorted_steps = sorted(steps, key=sort_key)

        # Number consecutively from 1
        numbered_steps: List[AuditStep] = []
        for idx, s in enumerate(sorted_steps, start=1):
            numbered_steps.append(
                AuditStep(
                    step_no=idx,
                    phase=s.phase,
                    system_id=s.system_id,
                    resource_id=s.resource_id,
                    operation=s.operation,
                    state=s.state,
                    evidence_id=s.evidence_id,
                )
            )

        return numbered_steps

    @classmethod
    def serialize_to_json(cls, steps: List[AuditStep]) -> str:
        """Serializes steps into a valid JSON array."""
        dicts = [s.to_dict() for s in steps]
        return json.dumps(dicts, separators=(",", ":"))
