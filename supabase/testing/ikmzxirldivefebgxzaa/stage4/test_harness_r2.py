"""Offline normalization/fail-closed tests using synthetic catalogs, never SQL."""
from pathlib import Path
import copy
import hashlib
import json
import re

ROOT=Path(__file__).resolve().parent
def recognized(row):
    return bool(re.fullmatch(r'pg_(temp|toast_temp)_[0-9]+',row['name'])) and bool(row['other_temp'] or row['my_temp'] or row['my_toast'])
def normalize(snapshot,catalog):
    result=copy.deepcopy(snapshot)
    ignore={r['oid'] for r in catalog if recognized(r)}
    result['native']['schemas']=[r for r in result['native']['schemas'] if r['oid'] not in ignore]
    return result

baseline={'effective':[{'allowed':False}], 'native':{'schemas':[{'oid':'1','owner':'postgres','acl':['existing']}], 'functions':[{'definition_md5':'fixed'}]}}
temp={'oid':'2','owner':'supabase_admin','acl':None}
actual=copy.deepcopy(baseline);actual['native']['schemas'].append(temp)
catalog=[dict(oid='2',name='pg_temp_11',other_temp=True,my_temp=False,my_toast=False)]
assert normalize(actual,catalog)==baseline
for name in ['pg_toast_temp_11','pg_temp_11']:
    for flag in ['other_temp','my_temp','my_toast']:
        row=dict(oid='2',name=name,other_temp=False,my_temp=False,my_toast=False);row[flag]=True
        assert normalize(actual,[row])==baseline
for name in ['business','pg_temp_evil','pg_toast_temp_11_extra']:
    row=dict(oid='2',name=name,other_temp=True,my_temp=False,my_toast=False)
    assert normalize(actual,[row])!=baseline
assert normalize(actual,[dict(oid='2',name='pg_temp_11',other_temp=False,my_temp=False,my_toast=False)])!=baseline
for field,value in [('owner','attacker'),('acl',['changed'])]:
    changed=copy.deepcopy(actual);changed['native']['schemas'][0][field]=value
    assert normalize(changed,catalog)!=baseline
changed=copy.deepcopy(actual);changed['native']['schemas'].pop(0)
assert normalize(changed,catalog)!=baseline
for category in ['effective','functions']:
    changed=copy.deepcopy(actual)
    if category=='effective':changed['effective'][0]['allowed']=True
    else:changed['native']['functions'][0]['definition_md5']='changed'
    assert normalize(changed,catalog)!=baseline
helper=(ROOT/'capture_comparison.sql').read_text()
assert "'{native,schemas}'" in helper
assert "pg_is_other_temp_schema(n.oid)" in helper and 'pg_my_temp_schema()' in helper
assert "^pg_(temp|toast_temp)_[0-9]+$" in helper
assert 'ORDER BY e.ordinality' in helper
for file in ['runtime.sql','guard.sql','cleanup_check.sql','../target_guard.psql']:
    text=(ROOT/file).read_text();assert '\\quit' not in text,file
assert (ROOT/'assert_comparison.sql').read_text().index('AS diagnostic;')<(ROOT/'assert_comparison.sql').read_text().index('RAISE EXCEPTION')
assert (ROOT/'runtime.sql').read_text().index('assert_comparison.sql')<(ROOT/'runtime.sql').read_text().index('\\ir fixture.sql')
assert 'evidence_r2' in (ROOT/'Invoke-Stage4.ps1').read_text()
manifest=json.loads((ROOT.parent/'stage4_diagnostics/diagnostic_manifest.json').read_text())
for file,key in [('evidence/runtime.receipt.json','failed_runtime_receipt_sha256'),('evidence/runtime.txt','failed_runtime_output_sha256'),('../stage3/evidence/verify_no_dml.txt','baseline_sha256')]:
    assert hashlib.sha256((ROOT/file).read_bytes()).hexdigest()==manifest[key]
preflight=(ROOT/'preflight_r2_read_only.sql').read_text()
assert not re.search(r'^\s*(BEGIN|COMMIT|ROLLBACK|SET|DO|CREATE|ALTER|DROP|INSERT|UPDATE|DELETE|GRANT|REVOKE)\b',preflight,re.M|re.I)
assert "90a71db3b16ed177b3455f61a59343b2" in preflight
print('PASS: temp-only normalization, persistent owner/ACL/add/drop checks, unrelated-field drift detection, fail-fast order, evidence preservation and SELECT-only preflight.')
