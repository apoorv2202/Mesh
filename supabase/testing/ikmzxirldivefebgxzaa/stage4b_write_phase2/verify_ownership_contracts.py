"""Independent read-only audit of actual reviewed transfers and both manifests.

Uses a separate, constrained transfer extractor rather than the generator parser.
Never imports generators, writes files, connects or executes database SQL.
"""
from pathlib import Path
import json
import re

HERE=Path(__file__).resolve().parent
PROPOSALS=HERE.parents[2]/'proposals/stage4b_write_phase2'

def canonical(t):
    t=re.sub(r'\s+',' ',t.strip().lower())
    return {'timestamptz':'timestamp with time zone','int':'integer','int4':'integer','bool':'boolean'}.get(t,t)

def verify():
    obj=json.loads((PROPOSALS/'object_contract.json').read_text())
    acl=json.loads((PROPOSALS/'acl_contract.json').read_text())
    transfers=[]
    for filename in ('03_machine_writer.sql','04_human_triage.sql'):
        sql=(PROPOSALS/filename).read_text()
        matches=list(re.finditer(r'^\s*ALTER\s+FUNCTION\s+([a-z_]\w*)\.([a-z_]\w*)\s*\(([^();]*)\)\s+OWNER\s+TO\s+([a-z_]\w*)\s*;',sql,re.M|re.I))
        assert len(matches)==len(re.findall(r'^\s*ALTER\s+FUNCTION\b',sql,re.M|re.I)),'Unrecognized actual transfer'
        for m in matches:
            schema,name,args,owner=m.groups()
            transfers.append(dict(schema=schema.lower(),name=name.lower(),arg_types=[canonical(x) for x in args.split(',') if x.strip()],owner=owner.lower()))
    assert transfers==obj['ownership_transfers'],'Transfer history differs from actual SQL'
    final={(s['schema'],s['name'],tuple(s['arg_types'])):s['owner'] for s in transfers}
    helpers={('vader_private','machine_scope_v1',()),('vader_private','human_guard_v1',('uuid','uuid')),
             ('vader_private','triage_token_v1',('text','jsonb'))}
    keys=set()
    for fn in obj['functions']:
        types=tuple(canonical(t) for t in fn['arg_types']);key=(fn['schema'],fn['name'],types)
        assert key not in keys,'Duplicate manifest signature';keys.add(key)
        if key in final:expected=final[key]
        else:
            assert key in helpers,'Silent creator-owner fallback'
            expected='postgres'
        assert fn['owner']==expected,(key,fn['owner'],expected)
        identity=fn['schema']+'.'+fn['name']+'('+', '.join(types)+')'
        rows=[r for r in acl['add'] if r[0]=='function' and r[1]==identity]
        assert rows,'Function ACL missing'
        assert sum(r==['function',identity,'',expected,expected,'EXECUTE',False] for r in rows)==1,'Owner ACL tuple mismatch'
        assert all(r[3]==expected and r[5]=='EXECUTE' and r[6] is False for r in rows),'Function ACL grantor/option mismatch'
    assert set(final)<=keys and helpers<=keys
    for name,tag,data in [('assert_object_contract.sql','contract',obj),('assert_acl_exact.sql','acl_contract',acl)]:
        text=(HERE/name).read_text();marker='$'+tag+'$'
        embedded=text.split(marker)
        assert len(embedded)==3 and json.loads(embedded[1])==data,'Generated assertion manifest stale: '+name
    print(f'Ownership audit PASS: {len(transfers)} explicit SQL transfers; {len(keys)} object and ACL signatures agree; 3 explicit creator-owned helpers.')
    return len(transfers),len(keys)

if __name__=='__main__':verify()
