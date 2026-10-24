import csv
import json

rows = list(csv.DictReader(open('output.csv', encoding='utf-8')))
print(f"Total rows: {len(rows)}")
print(f"Header: {list(rows[0].keys())}")
statuses = {}
for r in rows:
    statuses[r['deletion_status']] = statuses.get(r['deletion_status'], 0) + 1
print(f"Statuses breakdown: {statuses}")
for cid in ['case_533', 'case_535', 'case_540', 'case_541']:
    r = next(row for row in rows if row['case_id'] == cid)
    print(f"{cid}: status={r['deletion_status']} steps={r['steps_json']}")
