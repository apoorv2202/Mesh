"""Offline preparation only: derive reviewed transaction body, never execute SQL."""
from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parent
proposal = ROOT.parents[2] / 'proposals/01_vader_security_hardening.sql'
raw = proposal.read_bytes()
sql = raw.decode().replace('\r\n', '\n')
assert len(re.findall(r'^BEGIN;$', sql, re.M)) == 1
assert len(re.findall(r'^COMMIT;$', sql, re.M)) == 1
body = re.sub(r'^BEGIN;\n', '', sql, count=1, flags=re.M)
body = re.sub(r'^COMMIT;\s*$', '', body, count=1, flags=re.M)
(ROOT / 'migration01_body.sql').write_text('-- Generated exact proposal body; only outer BEGIN/COMMIT removed.\n'+body, encoding='utf-8', newline='\n')
start = '''\\ir guard.sql
BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='60s';
LOCK TABLE public.security_events,public.security_findings,public.security_incidents,
 public.incident_events,public.security_risk_scores IN ACCESS EXCLUSIVE MODE;
\\ir snapshot.sql
SELECT md5(:'snapshot')=:'expected_baseline_md5' AS baseline_unchanged \\gset
\\if :baseline_unchanged
\\else
\\echo Baseline drift; STOP before migration.
\\quit 3
\\endif
SELECT set_config('mesh_stage3.before', :'snapshot', true) AS ignored \\gset
\\ir assert_baseline.sql
\\ir dml_probes.sql
SELECT set_config('mesh_review.security_approved','on',true) AS ignored \\gset
'''
change = '''\\ir migration01_body.sql
\\ir snapshot.sql
SELECT set_config('mesh_stage3.after', :'snapshot', true) AS ignored \\gset
\\ir assert_hardened.sql
\\ir dml_probes.sql
'''
rollback = start+'''SAVEPOINT before_migration;
'''+change+'''-- Only this exact intentional exception may be tolerated.
\\set ON_ERROR_STOP off
DO $abort$ BEGIN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='VADER_STAGE3_INTENTIONAL_ABORT'; END $abort$;
\\set intentional_state :SQLSTATE
\\set ON_ERROR_STOP on
ROLLBACK TO SAVEPOINT before_migration;
SELECT :'intentional_state'='P0001' AS expected_abort \\gset
\\if :expected_abort
\\else
\\quit 3
\\endif
\\ir snapshot.sql
SELECT set_config('mesh_stage3.restored', :'snapshot', true) AS ignored \\gset
DO $restore$ BEGIN
 IF current_setting('mesh_stage3.before')::jsonb IS DISTINCT FROM current_setting('mesh_stage3.restored')::jsonb THEN
 RAISE EXCEPTION 'Rollback did not exactly restore baseline'; END IF;
END $restore$;
\\ir assert_baseline.sql
SELECT jsonb_build_object('test','rollback','restored',true,'baseline',current_setting('mesh_stage3.before')::jsonb) AS result;
ROLLBACK;
'''
(ROOT/'rollback.sql').write_text(rollback,encoding='utf-8',newline='\n')
(ROOT/'apply.sql').write_text(start+change+'''SELECT jsonb_build_object('test','apply_precommit','before',current_setting('mesh_stage3.before')::jsonb,'after',current_setting('mesh_stage3.after')::jsonb) AS result;
COMMIT;
SELECT 'MIGRATION01_COMMIT_ACKNOWLEDGED';
''',encoding='utf-8',newline='\n')
(ROOT/'baseline.sql').write_text('''\\ir guard.sql
BEGIN READ ONLY;
\\ir snapshot.sql
SELECT set_config('mesh_stage3.before', :'snapshot', true) AS ignored \\gset
\\ir assert_baseline.sql
SELECT jsonb_build_object('snapshot',:'snapshot'::jsonb,'snapshot_md5',md5(:'snapshot')) AS result;
ROLLBACK;
''',encoding='utf-8',newline='\n')
(ROOT/'verify.sql').write_text('''\\ir guard.sql
BEGIN READ ONLY;
\\ir snapshot.sql
SELECT set_config('mesh_stage3.before', :'snapshot', true) AS ignored \\gset
SELECT set_config('mesh_stage3.after', :'snapshot', true) AS ignored \\gset
\\ir assert_hardened.sql
SELECT :'snapshot'::jsonb AS result;
ROLLBACK;
''',encoding='utf-8',newline='\n')
(ROOT/'dml.sql').write_text('''\\ir guard.sql
BEGIN;
SET LOCAL statement_timeout='60s';
\\ir dml_probes.sql
SELECT jsonb_build_object('test','dml','passed',true,'probes',100) AS result;
ROLLBACK;
''',encoding='utf-8',newline='\n')
gate = re.search(r'DO \$guard\$.*?\$guard\$;',body,re.S).group()
(ROOT/'gate.sql').write_text('''\\ir guard.sql
BEGIN;
\\ir snapshot.sql
SELECT set_config('mesh_stage3.before', :'snapshot', true) AS ignored \\gset
SELECT set_config('mesh_review.security_approved','off',true) AS ignored \\gset
DO $test$
BEGIN
 BEGIN
 EXECUTE $tested$'''+gate+'''$tested$;
 RAISE EXCEPTION 'Expected closed-gate failure did not occur';
 EXCEPTION WHEN SQLSTATE 'P0001' THEN
  IF SQLERRM<>'Review-only proposal: security review gate is closed' THEN RAISE; END IF;
 END;
END $test$;
\\ir snapshot.sql
SELECT set_config('mesh_stage3.restored', :'snapshot', true) AS ignored \\gset
DO $restore$ BEGIN
 IF current_setting('mesh_stage3.before')::jsonb IS DISTINCT FROM current_setting('mesh_stage3.restored')::jsonb THEN
 RAISE EXCEPTION 'Closed-gate test changed metadata'; END IF;
END $restore$;
SELECT jsonb_build_object('test','closed_gate','passed',true,'expected_sqlstate','P0001') AS result;
ROLLBACK;
''',encoding='utf-8',newline='\n')
pins = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in ROOT.iterdir() if p.suffix in {'.sql','.ps1','.py'}}
pins['../target_guard.psql']=hashlib.sha256((ROOT.parent/'target_guard.psql').read_bytes()).hexdigest()
(ROOT/'pins.json').write_text(json.dumps({'test_ref':'ikmzxirldivefebgxzaa','proposal_sha256':hashlib.sha256(raw).hexdigest(),'files':pins},indent=2)+'\n',encoding='utf-8',newline='\n')
print('Prepared pinned Stage 3 scripts locally. NO SQL executed.')
