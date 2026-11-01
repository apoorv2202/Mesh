"""Offline review: no SQL execution, network, credentials or original-file edits."""
from pathlib import Path
import hashlib
import json
import re

ROOT=Path(__file__).resolve().parent
pins=json.loads((ROOT/'pins_no_dml.json').read_text())
for name,digest in pins['files'].items():
    assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==digest,name
raw=(ROOT/'apply.sql').read_bytes()
variant=(ROOT/'apply_no_dml.sql').read_bytes()
assert raw.count(b'\\ir dml_probes.sql\n')==2
assert variant==raw.replace(b'\\ir dml_probes.sql\n',b'')
def closure(name,seen=None):
    seen=set() if seen is None else seen
    path=(ROOT/name).resolve()
    if path in seen:return seen
    seen.add(path)
    for child in re.findall(r'^\\ir (.+)$',path.read_text(),re.M):
        assert (path.parent/child).resolve().is_file()
        closure(str((path.parent/child).resolve()),seen)
    return seen
for entry in ('apply_no_dml.sql','verify.sql'):
    paths=closure(entry)
    assert not any('dml_probes' in p.name or p.name in {'dml.sql','rls.sql','apply.sql'} for p in paths)
    for path in paths:
        sql=path.read_text()
        # Exclude comments/string bodies only for anchored executable statements;
        # actual included DO bodies are reviewed as well, not treated as opaque.
        assert not re.search(r'^\s*(INSERT\s+INTO|UPDATE\s+public\.|DELETE\s+FROM|TRUNCATE\s+(?:TABLE\s+)?public\.|CREATE\s+(?:TABLE|FUNCTION|ROLE)|ALTER\s+(?:ROLE|TABLE))',sql,re.M|re.I),path
        assert not re.search(r'\\(?:i|ir)\s+.*(?:02_|writer|dml|rls\.sql)',sql,re.I),path
    print(entry,'reviewed include closure:',', '.join(sorted(p.name for p in paths)))
text=variant.decode()
assert text.count('\nBEGIN;')==1 and text.count('\nCOMMIT;')==1
assert text.index('assert_hardened.sql')<text.index('\nCOMMIT;')
assert 'expected_baseline_md5' in text and 'ON_ERROR_STOP on' in (ROOT/'guard.sql').read_text()
launcher=(ROOT/'Invoke-Migration01NoDml.ps1').read_text()
assert "[ValidateSet('Validate','ApplyNoDml','VerifyNoDml')]" in launcher
assert '$sql)' in launcher and "{'apply_no_dml.sql'} else {'verify.sql'}" in launcher
for phase in ('baseline','gate','rollback'):
    receipt=json.loads((ROOT/f'evidence/{phase}.receipt.json').read_text(encoding='utf-8-sig'))
    assert receipt['passed'] and receipt['test_ref']==pins['test_ref']
    assert receipt['proposal_sha256']==pins['proposal_sha256']
    assert receipt['output_sha256']==hashlib.sha256((ROOT/f'evidence/{phase}.txt').read_bytes()).hexdigest()
b=json.loads((ROOT/'evidence/baseline.txt').read_text(encoding='utf-8-sig'))
r=json.loads((ROOT/'evidence/rollback.txt').read_text(encoding='utf-8-sig'))
assert b['snapshot']==r['baseline'] and r['restored']
print('PASS: exact two-line removal; originals/pins/evidence unchanged; allowed include paths; fail-fast, transaction and assertions preserved.')
print('NOT EXECUTED: variant PostgreSQL runtime and post-commit verification. New execution authorization required.')
