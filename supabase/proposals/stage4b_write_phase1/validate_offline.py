"""Read files only; no SQL compilation, database clients, network or runtime harness."""
from pathlib import Path
import hashlib
import json
import re

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
read = REPO / 'supabase/testing/ikmzxirldivefebgxzaa/stage4b_read'
pins = json.loads((read / 'pins.json').read_text())['files']
for name, expected in pins.items():
    assert hashlib.sha256((read / name).read_bytes()).hexdigest() == expected, name
print(f'Historical Stage 4B-read pins: {len(pins)}/{len(pins)} match')
source = json.loads((HERE / 'machine_revision_source.json').read_text())
assert hashlib.sha256((HERE.parent / '02_vader_transactional_writer.sql').read_bytes()).hexdigest() == source['original_proposal_sha256']
assert hashlib.sha256((HERE / '03_machine_writer_r2.sql').read_bytes()).hexdigest() == source['revised_candidate_sha256']
schema = json.loads((REPO / 'supabase/testing/ikmzxirldivefebgxzaa/stage4/verified_schema.json').read_text())
columns = {(r['table_name'], r['column_name']) for r in schema['02_columns']}
full = json.loads((REPO / 'supabase/inspection/mesh_inspection.json').read_text())
columns.update((r['table_name'], r['column_name']) for r in full['02_columns']['inspection'])
count = 0
for path in sorted(HERE.glob('*.sql')):
    sql = path.read_text()
    # Lexical smoke checks only, not a PostgreSQL parser.
    clean = re.sub(r'--[^\n]*', '', sql)
    assert clean.strip().startswith('BEGIN;') and clean.strip().endswith('COMMIT;'), path.name
    tags = re.findall(r'\$[A-Za-z_][A-Za-z_0-9]*\$|\$\$', clean)
    for tag in set(tags): assert tags.count(tag) % 2 == 0, (path.name, tag)
    assert 'mesh_review.test_ref' in sql and 'ikmzxirldivefebgxzaa' in sql
    assert not re.search(r'CREATE\s+ROLE\s+\w+\s+LOGIN\b', sql, re.I)
    assert not re.search(r'\b(?:DELETE\s+FROM|TRUNCATE\s+TABLE|DROP\s+SCHEMA)\b', clean, re.I)
    for table, names in re.findall(r'INSERT INTO public\.(\w+)\s*\(([^)]+)\)', clean):
        for name in names.split(','):
            assert (table, name.strip()) in columns, (path.name, table, name)
    for table, names in re.findall(r'GRANT INSERT\(([^)]+)\) ON public\.(\w+)', clean):
        # Regex captures column list first.
        for name in table.split(','): assert (names, name.strip()) in columns
    assert not re.search(r'GRANT\s+(?:INSERT|UPDATE|DELETE|ALL)\s+ON\s+public\.\w+\s+TO\s+authenticated', clean, re.I)
    count += 1
triage = (HERE / '04_human_triage.sql').read_text()
assert 'FOR SHARE' in triage and 'FOR UPDATE' in triage and "ERRCODE='40001'" in triage
assert 'prior_payload IS DISTINCT FROM request' in triage
machine = (HERE / '03_machine_writer_r2.sql').read_text()
for action in ('event_ingested', 'finding_created', 'incident_created', 'incident_link_created', 'risk_created'):
    assert f"append_machine_audit_v1('{action}'" in machine
print(f'{count} proposal files: lexical guards and captured INSERT column checks passed')
print('Original Migration02 hash preserved. NO PostgreSQL syntax/runtime validation claimed.')
