"""Offline tests only. No SQL, network, launcher invocation or fixture writes."""
from pathlib import Path
import ast
import copy
import hashlib
import json
import re

ROOT=Path(__file__).resolve().parent
pins=json.loads((ROOT/'pins.json').read_text())
for name,digest in pins['files'].items():assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==digest,name
def closure(p,seen=None):
    seen=set() if seen is None else seen;p=p.resolve()
    if p in seen:return seen
    seen.add(p)
    for name in re.findall(r'^\\ir (.+)$',p.read_text(),re.M):closure(p.parent/name,seen)
    return seen
for entry in ['runtime.sql','cleanup_check.sql']:
    for path in closure(ROOT/entry):
        text=path.read_text()
        assert not re.search(r'^\s*(COMMIT|CREATE|ALTER|DROP|REVOKE|TRUNCATE|CALL)\b',text,re.M|re.I),path
        assert not re.search(r'^\s*(INSERT INTO|UPDATE|DELETE FROM)\s+auth\.',text,re.M|re.I),path
        assert 'nextval(' not in text and 'setval(' not in text
        if re.search(r'^GRANT\b',text,re.M):assert path.name=='grant_select_proposal.sql'
    print(entry,'closure checked')
grant=(ROOT/'grant_select_proposal.sql').read_text()
assert re.findall(r'^GRANT\s+(\w+)',grant,re.M)==['SELECT']
assert 'TO authenticated;' in grant and 'WITH GRANT OPTION' not in grant
assert set(re.findall(r'public\.([a-z_]+)',grant))=={'security_events','security_findings','security_incidents','incident_events','security_risk_scores'}
cases=json.loads((ROOT/'test_matrix.json').read_text());assert len(cases)==14
assert sum(5 if c['identity']=='invalid' else 45 for c in cases)==590
assert {'owner','hr','senior_developer','junior_developer','suspended','offboarded','missing_identity','invalid_identity','metadata_role_escalation'}<={c['name'] for c in cases}
sql=(ROOT/'runtime.sql').read_text();assert sql.count('\nBEGIN;')==1 and sql.count('\nROLLBACK;')==1
assert sql.index('SAVEPOINT read_fixture')<sql.index('grant_select_proposal.sql')<sql.index('assert_delta.sql')<sql.index('select_tests.sql')<sql.index('ROLLBACK TO SAVEPOINT read_fixture;')
assert 'OVERRIDING SYSTEM VALUE' in (ROOT/'fixture.sql').read_text()
assert '44444444-4444-4444-8444-' not in (ROOT/'fixture.sql').read_text()
for path in ROOT.glob('*.py'):ast.parse(path.read_text())
# Model exact authorized delta and inject unintended grants/owner/policy changes.
b={'native':{'policies':['fixed']},'column_acls':None,'effective':[dict(rolname=r,relname=str(t),privilege=p,allowed=r=='postgres') for r in ['anon','authenticated','authenticator','service_role','postgres'] for t in range(5) for p in ['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN']],
 'target_acls':[{'table':str(t),'owner':'postgres','acl':['postgres=arwdDxtm/postgres']} for t in range(5)]}
def allowed(before,after):
    expected=copy.deepcopy(before)
    for c in expected['effective']:
        if c['rolname']=='authenticated' and c['privilege']=='SELECT':c['allowed']=True
    for c in expected['target_acls']:c['acl'].append('authenticated=r/postgres')
    return expected==after
a=copy.deepcopy(b)
for c in a['effective']:
    if c['rolname']=='authenticated' and c['privilege']=='SELECT':c['allowed']=True
for c in a['target_acls']:c['acl'].append('authenticated=r/postgres')
assert allowed(b,a)
for role,priv in [('anon','SELECT'),('service_role','SELECT'),('authenticated','INSERT'),('authenticated','UPDATE'),('authenticated','TRIGGER'),('authenticated','MAINTAIN')]:
    bad=copy.deepcopy(a)
    next(c for c in bad['effective'] if c['rolname']==role and c['privilege']==priv)['allowed']=True
    assert not allowed(b,bad)
bad=copy.deepcopy(a);bad['target_acls'][0]['acl'][-1]='authenticated=r*/postgres';assert not allowed(b,bad)
bad=copy.deepcopy(a);bad['native']['policies']=['weakened'];assert not allowed(b,bad)
assert allowed(b,copy.deepcopy(a)) and b==json.loads(json.dumps(b))
print('PASS: pins, includes, single SELECT-only delta, case/count coverage, transaction ordering, mutation rejection models and Python AST.')
print('NOT TESTED: PostgreSQL compilation, actual grants/RLS reads/rollback, JWT/API auth. NO SQL executed.')
