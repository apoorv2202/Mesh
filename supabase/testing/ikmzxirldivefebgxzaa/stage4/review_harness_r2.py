"""One-time offline, allowlisted repinning of the explicitly authorized correction."""
from pathlib import Path
import hashlib
import json

ROOT=Path(__file__).resolve().parent
old_bytes=(ROOT/'pins.json').read_bytes()
old=json.loads(old_bytes)
assert old.get('harness_revision',1)==1,'Already updated; never refresh reviewed pins automatically'
modified={'runtime.sql','guard.sql','cleanup_check.sql','../target_guard.psql','Invoke-Stage4.ps1','validate_stage4.py'}
new={'capture_comparison.sql','assert_comparison.sql','Stage4-Results.ps1','Test-Stage4Offline.ps1',
     'test_harness_r2.py','review_harness_r2.py','prepare_preflight_r2.py','preflight_r2_read_only.sql'}
history=ROOT/'review_history';history.mkdir(exist_ok=True)
archive=history/'pins_before_r2.json'
if archive.exists():assert archive.read_bytes()==old_bytes
else:
    with archive.open('xb') as out:out.write(old_bytes)
for name,digest in old['files'].items():
    actual=hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
    if name not in modified:assert actual==digest,('UNAPPROVED file change',name)
manifest=json.loads((ROOT.parent/'stage4_diagnostics/diagnostic_manifest.json').read_text())
for name,key in [('evidence/runtime.receipt.json','failed_runtime_receipt_sha256'),('evidence/runtime.txt','failed_runtime_output_sha256')]:
    assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==manifest[key]
assert hashlib.sha256((ROOT.parent/'stage3/evidence/verify_no_dml.txt').read_bytes()).hexdigest()==manifest['baseline_sha256']
files=dict(old['files'])
for name in modified|new:files[name]=hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
files['review_history/pins_before_r2.json']=hashlib.sha256(old_bytes).hexdigest()
files['evidence/runtime.receipt.json']=manifest['failed_runtime_receipt_sha256']
files['evidence/runtime.txt']=manifest['failed_runtime_output_sha256']
updated={'test_ref':old['test_ref'],'harness_revision':2,'expected_baseline_md5':manifest['expected_baseline_md5'],
 'reviewed_modified_files':sorted(modified),'reviewed_new_files':sorted(new),'files':files}
(ROOT/'pins.json').write_text(json.dumps(updated,indent=2)+'\n',encoding='utf-8',newline='\n')
print('Reviewed allowlist updated. Historical baseline/receipts and old pins preserved. No SQL executed.')
