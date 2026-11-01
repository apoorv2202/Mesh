"""Offline catalog/source/safety validation. Never executes SQL or HTTP."""
from pathlib import Path
import ast
import hashlib
import json
import re

ROOT=Path(__file__).resolve().parent
pins=json.loads((ROOT/'pins.json').read_text())
for name,digest in pins['files'].items():
    assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==digest,name
def closure(path,seen=None):
    seen=set() if seen is None else seen
    path=path.resolve()
    if path in seen:return seen
    seen.add(path)
    for include in re.findall(r'^\\ir (.*)$',path.read_text(),re.M):
        closure(path.parent/include,seen)
    return seen
for name in ['runtime.sql','cleanup_check.sql']:
    for path in closure(ROOT/name):
        text=path.read_text()
        assert not re.search(r'^\s*(COMMIT|GRANT|REVOKE|CREATE|ALTER|DROP|TRUNCATE)\b',text,re.M|re.I),path
        assert not re.search(r'\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+auth\.',text,re.I),path
        assert 'setval(' not in text and 'nextval(' not in text
    print(name,'include closure PASS: no commit/DDL/grant changes/managed Auth writes/sequence mutation')
sql=(ROOT/'runtime.sql').read_text()
assert sql.count('\nBEGIN;')==1 and sql.count('\nROLLBACK;')==1
assert sql.index('ROLLBACK TO SAVEPOINT fixture;')<sql.index('Metadata/grants/roles/policies changed')
assert 'OVERRIDING SYSTEM VALUE' in (ROOT/'fixture.sql').read_text()
assert (ROOT/'fk_tests.sql').read_text().count('GET STACKED DIAGNOSTICS')==10
assert "count_tests<>480" in (ROOT/'acl_tests.sql').read_text()
catalog=json.loads((ROOT.parent/'post_bootstrap_verification.json').read_text(encoding='utf-8-sig'))
fixture=(ROOT/'fixture.sql').read_text()
for table,columns in re.findall(r'INSERT INTO public\.([a-z_]+)\(([^)]+)\)',fixture):
    known={r['column_name'] for r in catalog['02_columns']['inspection'] if r['table_name']==table}
    assert set(columns.split(','))<=known,(table,columns)
facts=json.loads((ROOT/'verified_schema.json').read_text())
assert [len(facts[k]) for k in ['02_columns','03_constraints','04_indexes','10_policies']]==[57,31,15,5]
assert 'Exact target column/type/default/nullability/identity drift' in (ROOT/'assert_schema.sql').read_text()
assert pins['harness_revision']==2
for name in ['runtime.sql','cleanup_check.sql','guard.sql','../target_guard.psql']:
    assert '\\quit' not in (ROOT/name).read_text(),name
assert "'{native,schemas}'" in (ROOT/'capture_comparison.sql').read_text()
assert 'capture_comparison.sql' in (ROOT/'runtime.sql').read_text()
for path in ROOT.glob('*.py'):ast.parse(path.read_text())
post=json.loads((ROOT.parent/'stage3/evidence/verify_no_dml.txt').read_text(encoding='utf-8-sig'))
receipt=json.loads((ROOT.parent/'stage3/evidence/verify_no_dml.receipt.json').read_text(encoding='utf-8-sig'))
assert receipt['passed'] and receipt['test_ref']==pins['test_ref']
assert receipt['output_sha256']==hashlib.sha256((ROOT.parent/'stage3/evidence/verify_no_dml.txt').read_bytes()).hexdigest()
assert not any(r['allowed'] for r in post['effective'] if r['rolname'] in ['anon','authenticated','service_role'])
print('PASS: hashes, post-M01 evidence, SQL scope/order and Python AST. PostgreSQL/HTTP/runtime NOT EXECUTED.')
