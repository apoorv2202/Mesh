"""Offline static checks; no PostgreSQL connection, subprocess or SQL execution."""
from pathlib import Path
import ast
import hashlib
import json
import re

ROOT=Path(__file__).resolve().parent
pins=json.loads((ROOT/'pins.json').read_text())
for name, digest in pins['files'].items():
    assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==digest,name
proposal=(ROOT.parents[2]/'proposals/01_vader_security_hardening.sql').read_bytes()
assert hashlib.sha256(proposal).hexdigest()==pins['proposal_sha256']
source=proposal.decode().replace('\r\n','\n')
expected=re.sub(r'^BEGIN;\n','',source,count=1,flags=re.M)
expected=re.sub(r'^COMMIT;\s*$','',expected,count=1,flags=re.M)
assert (ROOT/'migration01_body.sql').read_text().split('\n',1)[1]==expected
for path in ROOT.glob('*.sql'):
    text=path.read_text()
    for include in re.findall(r'^\\ir (.+)$',text,re.M):
        assert (ROOT/include).resolve().is_file(),include
    assert not re.search(r'\b(?:ALTER|GRANT|REVOKE)\s+ROLE\b',text,re.I)
    assert not re.search(r'\b(?:DISABLE|FORCE|NO FORCE) ROW LEVEL SECURITY\b',text,re.I)
    # Balanced SQL strings/dollar bodies and parentheses (not a SQL compiler).
    tokens=re.finditer(r"--[^\n]*|^\\[^\n]*|'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|\$([A-Za-z_][A-Za-z_0-9]*|)\$|[()]",text,re.M)
    skip=0; depth=0
    for token in tokens:
        if token.start()<skip: continue
        value=token.group()
        if value.startswith('$'):
            end=text.find(value,token.end()); assert end>=0,(path.name,value)
            skip=end+len(value)
        elif value=='(':depth+=1
        elif value==')':depth-=1;assert depth>=0,path.name
    assert depth==0,path.name
for name in ['apply.sql','rollback.sql']:
    text=(ROOT/name).read_text()
    assert text.count('\nBEGIN;')==1
    assert 'expected_baseline_md5' in text
    assert text.index('assert_hardened.sql')<text.rfind('COMMIT;' if name=='apply.sql' else 'ROLLBACK;')
assert (ROOT/'rollback.sql').read_text().count('\\set ON_ERROR_STOP off')==1
assert 'ROLLBACK TO SAVEPOINT before_migration;' in (ROOT/'rollback.sql').read_text()
assert 'COMMIT;' not in (ROOT/'rls.sql').read_text()
for name in ['baseline.sql','verify.sql']:
    text=(ROOT/name).read_text();assert 'BEGIN READ ONLY;' in text and 'dml_probes.sql' not in text
for path in ROOT.glob('*.py'):ast.parse(path.read_text())
print('PASS: pinned proposal/body correspondence, includes, transaction/abort gates, no managed-role/RLS changes, lexical checks and Python AST.')
print('LIMIT: PostgreSQL/PLpgSQL execution and live privileges/RLS/rollback remain UNTESTED. No SQL executed.')
