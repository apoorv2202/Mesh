"""Static checks only. No psql, SQL, launcher, network or runtime harness calls."""
from pathlib import Path
import hashlib
import json
import re
import sys
from gate_state import load_preparation

prepin=sys.argv[1:]==['--preparing-eligibility-repin']
helper_repin=sys.argv[1:]==['--preparing-helper-repin']
if sys.argv[1:] and not (prepin or helper_repin):raise ValueError('Unknown offline validation option')

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[3]
PROPOSALS=REPO/'supabase/proposals/stage4b_write_phase2'
OLD=PROPOSALS.parent/'stage4b_write_phase1'
for manifest, base in [(OLD/'preparation_pins.json',OLD),
 (HERE.parent/'stage4b_read/pins.json',HERE.parent/'stage4b_read')]:
    pins=json.loads(manifest.read_text())['files']
    for name,digest in pins.items():
        assert hashlib.sha256((base/name).read_bytes()).hexdigest()==digest,name
    print(f'Preserved manifest {manifest.name}: {len(pins)} hashes match')
for name,digest in json.loads((PROPOSALS/'source_hashes.json').read_text()).items():
    assert hashlib.sha256((OLD/name).read_bytes()).hexdigest()==digest,name
for phase in ('runtime','cleanup_check'):
    evidence=HERE.parent/'stage4b_read/evidence'
    receipt=json.loads((evidence/(phase+'.receipt.json')).read_text(encoding='utf-8-sig'))
    assert receipt['passed'] and receipt['test_ref']=='ikmzxirldivefebgxzaa'
    assert receipt['output_sha256']==hashlib.sha256((evidence/(phase+'.txt')).read_bytes()).hexdigest()
print('Stage 4B-read closure receipts/log hashes preserved and valid')
from verify_ownership_contracts import verify
verify()

def mask(sql):
    # Mask comments, quoted strings and dollar bodies for transaction-token checks.
    token=re.compile(r"--[^\n]*|/\*[\s\S]*?\*/|'(?:''|[^'])*'|\$(?P<tag>[a-zA-Z_][\w]*)?\$[\s\S]*?\$(?P=tag)\$",re.M)
    return token.sub(' ',sql)

visited=set()
def inspect(path):
    path=path.resolve()
    if path in visited:return
    assert path.is_file(),path
    visited.add(path)
    sql=path.read_text()
    if path.suffix=='.psql' and '.body.' in path.name:
        assert not re.search(r'^\s*(?:BEGIN|COMMIT|END|START TRANSACTION|ROLLBACK)\s*;',mask(sql),re.M|re.I),path
    assert not re.search(r'\\(?:i|include)\s',sql),path
    assert not re.search(r'\\(?:!|connect|c|copy|quit|q)\b',sql),path
    for child in re.findall(r'^\\ir\s+(\S+)',sql,re.M):inspect(path.parent/child)
inspect(HERE/'runtime.sql');inspect(HERE/'cleanup_check.sql')
runtime=(HERE/'runtime.sql').read_text()
assert len(re.findall(r'^BEGIN;',runtime,re.M))==1
assert not re.search(r'^\s*COMMIT\b',runtime,re.M|re.I)
assert runtime.count("SELECT 'STAGE4B_WRITE_ROLLBACK_ACKNOWLEDGED';")==1
assert runtime.index('SAVEPOINT write_scope;')<runtime.index('01_audit_permissions.body.psql')
assert runtime.index('ROLLBACK TO SAVEPOINT write_scope;')<runtime.index('\\set metadata_phase restored')<runtime.index('ROLLBACK;')
assert 'BEGIN READ ONLY;' in (HERE/'cleanup_check.sql').read_text()
print('Validated preparation state:',load_preparation(HERE))
launcher=(HERE/'Invoke-WriteRollback.ps1').read_text()
assert "PGUSER='postgres.ikmzxirldivefebgxzaa'" in launcher
assert "PGSSLMODE='verify-full'" in launcher
assert "'-X','-W'" in launcher
assert launcher.index('$exitCode -ne 0')<launcher.index('ConvertFrom-Json',launcher.index('$exitCode=$LASTEXITCODE'))
assert '[IO.FileMode]::CreateNew' in launcher
# No broad native schema/function ACL additions in the new candidate.
machine=(PROPOSALS/'03_machine_writer.sql').read_text()
assert 'GRANT EXECUTE ON FUNCTION extensions.' not in machine
assert 'GRANT USAGE ON SCHEMA vader_private,vader_api,public,extensions' not in machine
assert 'GRANT USAGE ON SCHEMA extensions TO vader_writer_owner;' in machine
assert "SET LOCAL createrole_self_grant='set,inherit';" in machine
triage=(PROPOSALS/'04_human_triage.sql').read_text()
assert "before_state-'revision'" in triage and 'current_revision+1' in triage
assert "prior NOT IN ('resolved','false_positive','accepted_risk')" in triage
assert "SET LOCAL createrole_self_grant='set,inherit';" in triage
assert '\\ir assert_acl_exact.sql' in (HERE/'assert_delta.sql').read_text()
assert '\\ir assert_memberships.sql' in (HERE/'assert_delta.sql').read_text()
acl=json.loads((PROPOSALS/'acl_contract.json').read_text())
assert acl['tuple_fields']==['kind','object','column','grantor','grantee','privilege','grantable']
assert len(acl['add'])==146 and all(row[-1] is False for row in acl['add'])
assert [r for r in acl['add'] if r[0]=='schema' and r[1]=='extensions']==[
 ['schema','extensions','','postgres','vader_writer_owner','USAGE',False]]
assert all(r[4]!='PUBLIC' for r in acl['add'])
assert 'n<>6' in (HERE/'assert_memberships.sql').read_text()
assert 'expected_write_acl_md5' in (HERE/'cleanup_check.sql').read_text()
assert "'column'" in (HERE/'capture_acl.sql').read_text()
for path in PROPOSALS.glob('*.sql'):
    text=path.read_text()
    assert text.count('BEGIN;')>=1 and text.rstrip().endswith('COMMIT;')
    assert 'mesh_review.test_ref' in text
for path in PROPOSALS.glob('*.body.psql'):
    source=PROPOSALS/path.name.replace('.body.psql','.sql')
    candidate=source.read_text().replace('-- Phase2 candidate; not executed.\n','',1)
    expected=re.sub(r'^BEGIN;\s*$','',candidate,count=1,flags=re.M)
    expected=re.sub(r'^COMMIT;\s*$','',expected,count=1,flags=re.M)
    assert path.read_text()==expected,path
print(f'Include closure: {len(visited)} files checked; no transaction-breaking include/control commands.')
new_pins=HERE/'pins.json'
if new_pins.exists():
    pinned=json.loads(new_pins.read_text())['files']
    allowed={HERE/'execution_readiness.json',HERE/'README.md',HERE/'update_preparation_pins.py',
             HERE/'validate_offline.py',PROPOSALS/'changed_preparation_files.json'}
    changed=[]
    for name,digest in pinned.items():
        path=(HERE/name).resolve()
        if hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            if helper_repin:
                approved=json.loads((PROPOSALS/'membership_fix_inventory.json').read_text())['modified']
                assert path in {(REPO/n).resolve() for n in approved},'Unapproved helper correction: '+name
            elif not prepin or path not in {p.resolve() for p in allowed}:raise ValueError('Unapproved pin mismatch: '+name)
            changed.append(name)
    print(f'Phase2 pins: {len(pinned)} checked; permitted local pre-repin changes: {len(changed)}')
print('Static checks passed. PostgreSQL syntax, role transfer, deparsing and runtime not verified.')
