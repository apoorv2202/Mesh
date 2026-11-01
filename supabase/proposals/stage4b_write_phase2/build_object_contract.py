"""Freeze reviewed function bodies/identity and policy inventory; offline only."""
from pathlib import Path
import json
import re
from ownership_parser import parse_sources,signature

HERE=Path(__file__).resolve().parent
TEST=HERE.parents[1]/'testing/ikmzxirldivefebgxzaa/stage4b_write_phase2'
sources=[];policies=[]
for filename in ('03_machine_writer.sql','04_human_triage.sql'):
    sql=(HERE/filename).read_text()
    sources.append(sql)
    for m in re.finditer(r'CREATE POLICY (\w+) ON (\w+)\.(\w+)\s+(?:FOR (SELECT|INSERT|UPDATE|DELETE)\s+)?TO (\w+)\s',sql):
        name,schema,table,command,role=m.groups()
        policies.append(dict(name=name,schema=schema,table=table,command={'SELECT':'r','INSERT':'a','UPDATE':'w','DELETE':'d',None:'*'}[command],role=role))
creator_owned={signature('vader_private',name,types):'postgres' for name,types in
 [('machine_scope_v1',[]),('human_guard_v1',['uuid','uuid']),('triage_token_v1',['text','jsonb'])]}
functions,transfers=parse_sources(sources,creator_owned,{'postgres','vader_writer_owner','vader_triage_owner'})
assert len(functions)==16 and len(policies)==20 and len(transfers)==13,(len(functions),len(policies),len(transfers))
manifest=json.dumps(dict(functions=functions,policies=policies,ownership_transfers=transfers),indent=2)
assert '$contract$' not in manifest
(HERE/'object_contract.json').write_text(manifest+'\n',encoding='utf8')
sql='''-- Exact function prosrc, argument OIDs/names, owner and mode from reviewed candidates.
DO $verify_objects$ DECLARE spec jsonb; f record; expected_types oid[]; expected_names text[]; p record;
 contract jsonb:=$contract$'''+manifest+'''$contract$::jsonb;
BEGIN
 FOR spec IN SELECT value FROM jsonb_array_elements(contract->'functions') LOOP
  SELECT coalesce(array_agg(to_regtype(x.value)::oid ORDER BY x.n),'{}'::oid[]) INTO expected_types
   FROM jsonb_array_elements_text(spec->'arg_types') WITH ORDINALITY x(value,n);
  SELECT array_agg(x.value ORDER BY x.n) INTO expected_names FROM jsonb_array_elements_text(spec->'arg_names') WITH ORDINALITY x(value,n);
  SELECT q.*,l.lanname INTO f FROM pg_proc q JOIN pg_namespace n ON n.oid=q.pronamespace JOIN pg_language l ON l.oid=q.prolang
   WHERE n.nspname=spec->>'schema' AND q.proname=spec->>'name' AND q.proargtypes::oid[]=expected_types;
  -- oidvector::oid[] can carry a zero lower bound: compare via ordered unnest below.
  IF NOT FOUND THEN
   SELECT q.*,l.lanname INTO f FROM pg_proc q JOIN pg_namespace n ON n.oid=q.pronamespace JOIN pg_language l ON l.oid=q.prolang
    WHERE n.nspname=spec->>'schema' AND q.proname=spec->>'name' AND
     ARRAY(SELECT unnest(q.proargtypes))=expected_types;
  END IF;
  IF NOT FOUND OR f.prosrc IS DISTINCT FROM spec->>'body' OR f.proargnames IS DISTINCT FROM expected_names
   OR f.prorettype<>to_regtype(spec->>'returns') OR f.lanname<>spec->>'language'
   OR pg_get_userbyid(f.proowner)<>spec->>'owner' OR f.prosecdef<>(spec->>'definer')::boolean
   OR f.proisstrict<>(spec->>'strict')::boolean OR f.provolatile::text<>spec->>'volatility' THEN
   RAISE EXCEPTION 'Exact function contract mismatch: %.%',spec->>'schema',spec->>'name'; END IF;
 END LOOP;
 FOR spec IN SELECT value FROM jsonb_array_elements(contract->'policies') LOOP
  SELECT * INTO p FROM pg_policy WHERE polrelid=to_regclass((spec->>'schema')||'.'||(spec->>'table')) AND polname=spec->>'name';
  IF NOT FOUND OR NOT p.polpermissive OR p.polcmd::text<>spec->>'command'
   OR p.polroles<>ARRAY[(SELECT oid FROM pg_roles WHERE rolname=spec->>'role')] THEN RAISE EXCEPTION 'Policy role/command inventory mismatch'; END IF;
 END LOOP;
END $verify_objects$;
'''
(TEST/'assert_object_contract.sql').write_text(sql,encoding='utf8',newline='\n')
print('Frozen 16 functions, 20 policies and 13 signature-matched ownership transfers offline.')
