# Ghost Data Deletion Audit Agent

A production-ready, autonomous AI compliance auditing system that proves whether a customer's personal data was truly and irreversibly deleted across distributed commerce platforms.

---

## 1. System Overview & Problem Formulation

In modern enterprise architectures, customer deletion workflows often report **"Complete"** while personal identifiers persist across read replicas, failover clusters, search indexes, analytics cohorts, support conversations, archives, and automated connectors. Furthermore, active background synchronization jobs and disaster recovery snapshots can recreate supposedly deleted records.

This agent acts as an independent compliance auditor that:
1. **Determines Deletion Intent**: Analyzes multilingual natural language requests to separate authorized account deletions from access, export, rectification, or opt-out inquiries (`NOT_APPLICABLE`).
2. **Reconstructs Identity Graphs**: Traces current and historical identifiers (names, emails, phones, email hashes, internal `user_id`s) through audit logs.
3. **Inspects Grounded Evidence**: Evaluates SQLite snapshots, observability logs, JSON records, and document attachments up to the case's point-in-time `audit_at` cutoff.
4. **Enforces Deletion Policies**: Applies data retention rules (e.g., retaining regulatory security audit logs, anonymizing product telemetry, redacting account tombstones while preserving internal IDs).
5. **Generates Ordered Remediation & Verification**: Emits structured finding, remediation, and verification steps complying with strict priority ordering.

---

## 2. Architecture & Modules

```text
ghost_data_audit_engine/
├── audit_engine/
│   ├── __init__.py            # Engine package exports
│   ├── models.py              # Strongly-typed data structures & enums
│   ├── identity_resolver.py   # Historical identity alias resolver
│   ├── intent_analyzer.py     # Multilingual NLP intent validator
│   ├── policy_engine.py       # Deletion rules & permissible retain rules
│   ├── evidence_indexer.py    # Multi-format SQLite & log trace indexer
│   ├── activity_indexer.py    # System activity timeline analyzer
│   ├── audit_orchestrator.py  # End-to-end case audit orchestrator
│   └── step_serializer.py     # Strict contract step sorter & JSON serializer
├── evaluation/
│   ├── __init__.py            # Evaluation package exports
│   ├── evaluator.py           # Precision, recall, sequence accuracy calculator
│   ├── evaluation_report.md   # Comprehensive evaluation benchmark report
│   └── usage_report.md        # Token usage and cost expenditure report
├── tests/
│   ├── __init__.py
│   └── test_audit.py          # Unit & integration test suite
├── main.py                    # Production CLI runner
├── output.csv                 # Generated submission predictions (518 cases)
└── README.md                  # System documentation
```

---

## 3. Quick Start & Execution

### Prerequisites
- Python 3.9+ (Python 3.10, 3.11, 3.12, 3.13, 3.14 fully supported)
- Built entirely on Python standard library (`sqlite3`, `csv`, `json`, `re`, `datetime`, `unittest`) with zero external dependencies.

### 1. Run Audit on Full Evaluation Dataset (518 Cases)
```bash
python main.py --requests deletion_requests.csv --output output.csv
```
This generates `output.csv` with exactly 518 data rows sorted by `case_id` in less than 1 second.

### 2. Run Audit with Evaluation Against Canonical Ground Truth
```bash
python main.py --requests sample_deletion_requests.csv --evaluate sample_output.csv --output sample_test_output.csv
```

### 3. Run Unit and Integration Test Suite
```bash
python -m unittest tests/test_audit.py
```

---

## 4. Contract Specification & Ordering Rules

Each row in `output.csv` follows this exact format:
```text
case_id,deletion_status,steps_json
```

### Phase Ordering
Every `steps_json` array is strictly ordered by phase:
1. `FINDING`: Discoveries of remaining records, exposed PII, active syncs, or restore risks.
2. `REMEDIATION`: Ordered actions (`DISABLE_DATA_FLOW`, `BLOCK_RESTORE`, `DELETE_RECORD`, `REDACT_RECORD`, `ANONYMIZE_RECORD`).
3. `VERIFICATION`: Post-remediation verification checks confirming compliant state.

Within each phase, operations are sorted according to the problem contract table priority, then by `system_id` (ascending), then by `resource_id` (ascending).
All steps feature consecutive 1-based numbering (`step_no`).

---

## 5. Authors & License
Built for HackerRank Orchestrate (Ghost Data Still Exists).
Licensed under MIT.
