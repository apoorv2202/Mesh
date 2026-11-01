"""Offline preparation only. Preserve every original reviewed Stage 3 artifact."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
original_pins = json.loads((ROOT/'pins.json').read_text())
for name, digest in original_pins['files'].items():
    assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest() == digest, name
raw = (ROOT/'apply.sql').read_bytes()
needle = b'\\ir dml_probes.sql\n'
assert raw.count(needle) == 2
(ROOT/'apply_no_dml.sql').write_bytes(raw.replace(needle,b''))
names = set(original_pins['files']) | {
    'pins.json','apply_no_dml.sql','Invoke-Migration01NoDml.ps1',
    'prepare_apply_no_dml.py','validate_apply_no_dml.py',
    '../bootstrap_execution_result.json',
}
for phase in ('baseline','gate','rollback'):
    names.update({f'evidence/{phase}.txt', f'evidence/{phase}.receipt.json'})
pins = {
    'test_ref': 'ikmzxirldivefebgxzaa',
    'proposal_sha256': original_pins['proposal_sha256'],
    'files': {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sorted(names)},
    'difference': 'apply.sql with exactly two complete \\ir dml_probes.sql lines removed; no other byte changes',
}
(ROOT/'pins_no_dml.json').write_text(json.dumps(pins,indent=2)+'\n',encoding='utf-8',newline='\n')
print('Offline preparation complete. Original artifacts unchanged. NO SQL executed.')
