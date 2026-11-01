"""Offline derivation only. Preserves Phase1 files, pins and historic evidence."""
from pathlib import Path
import hashlib
import json
import re

HERE = Path(__file__).resolve().parent
OLD = HERE.parent / 'stage4b_write_phase1'
inputs = {}

def load(name):
    data = (OLD / name).read_bytes()
    inputs[name] = hashlib.sha256(data).hexdigest()
    return data.decode().replace('\r\n', '\n')

def change(text, old, new, count=1):
    assert text.count(old) == count, old[:100]
    return text.replace(old, new)

audit = load('01_audit_permissions.sql')
audit = change(audit, "IF has_table_privilege(r,'public.audit_logs',p) THEN",
              "IF has_table_privilege(r,'public.audit_logs',p) OR (p IN ('INSERT','UPDATE','REFERENCES') AND has_any_column_privilege(r,'public.audit_logs',p)) THEN")
reference = load('02_reference_integrity.sql')
machine = load('03_machine_writer_r2.sql')
machine = change(machine, 'GRANT USAGE ON SCHEMA vader_private,vader_api,public,extensions TO vader_writer_owner;',
'''-- Narrow dependency grant: schema lookup for UUIDv5 and digest only.
-- No PUBLIC access, CREATE, grant option, or extension function ACL change.
GRANT USAGE ON SCHEMA extensions TO vader_writer_owner;
-- public USAGE already exists via PUBLIC; do not alter its ACL.
DO $usage$ BEGIN
 IF NOT has_schema_privilege('vader_writer_owner','public','USAGE')
 OR NOT has_schema_privilege('vader_writer_owner','extensions','USAGE') THEN
 RAISE EXCEPTION 'Native schema USAGE prerequisite absent'; END IF;
END $usage$;
GRANT USAGE ON SCHEMA vader_private,vader_api TO vader_writer_owner;''')
triage = load('04_human_triage.sql')
# Transaction-local PG17 provisioning. Only the three following NEW roles are
# created; existing roles/edges/attributes are never altered. Each role has a
# bootstrap ADMIN-only edge plus a postgres-granted SET/INHERIT-only edge. INHERIT is
# needed for subsequent owner-authorized REVOKE/GRANT without changing helper
# creation identity. Full rollback removes roles and all six new edges.
machine = change(machine, 'CREATE ROLE vader_writer_owner',
 "SET LOCAL createrole_self_grant='set,inherit';\nCREATE ROLE vader_writer_owner")
triage = change(triage, 'CREATE ROLE vader_triage_owner',
 "SET LOCAL createrole_self_grant='set,inherit';\nCREATE ROLE vader_triage_owner")
machine = change(machine, 'CREATE SCHEMA vader_private;', '''DO $ownership_capability$ BEGIN
 IF NOT pg_has_role('postgres','vader_writer_owner','SET')
 OR NOT pg_has_role('postgres','vader_writer_owner','USAGE') THEN
 RAISE EXCEPTION 'Scoped writer SET/INHERIT capability absent'; END IF;
END $ownership_capability$;
CREATE SCHEMA vader_private;''')
triage = change(triage, 'CREATE SCHEMA vader_user_api;', '''DO $ownership_capability$ BEGIN
 IF NOT pg_has_role('postgres','vader_triage_owner','SET')
 OR NOT pg_has_role('postgres','vader_triage_owner','USAGE') THEN
 RAISE EXCEPTION 'Scoped triage SET/INHERIT capability absent'; END IF;
END $ownership_capability$;
CREATE SCHEMA vader_user_api;''')
machine = change(machine, 'GRANT EXECUTE ON FUNCTION extensions.uuid_generate_v5(uuid,text),extensions.digest(bytea,text) TO vader_writer_owner;',
'''DO $extension_usage$ BEGIN
 IF NOT has_function_privilege('vader_writer_owner','extensions.uuid_generate_v5(uuid,text)','EXECUTE')
 OR NOT has_function_privilege('vader_writer_owner','extensions.digest(bytea,text)','EXECUTE') THEN
 RAISE EXCEPTION 'Existing extension EXECUTE prerequisite absent'; END IF;
END $extension_usage$;''')
triage = change(triage, 'GRANT EXECUTE ON FUNCTION public.is_mesh_member(uuid,public.mesh_role[]) TO vader_triage_owner;',
'''-- Only this existing helper ACL is extended; no definition/owner/settings change.
GRANT EXECUTE ON FUNCTION public.is_mesh_member(uuid,public.mesh_role[]) TO vader_triage_owner;
DO $member_usage$ BEGIN
 IF NOT has_function_privilege('vader_triage_owner','public.is_mesh_member(uuid,public.mesh_role[])','EXECUTE') THEN
 RAISE EXCEPTION 'Existing membership helper EXECUTE prerequisite absent'; END IF;
END $member_usage$;''')
triage = change(triage, "SELECT prior=next_state OR", "SELECT (prior=next_state AND prior NOT IN ('resolved','false_positive','accepted_risk')) OR")
anchor = '-- Core is private. Public API consists of separate, fixed-kind wrappers below.'
version_ddl = '''-- Revision protects against ABA; no application columns are repurposed.
CREATE TABLE vader_private.triage_versions (
 organization_id uuid NOT NULL REFERENCES public.organizations(id),
 operation text NOT NULL CHECK(operation IN ('finding','incident')),
 target_id uuid NOT NULL,
 revision bigint NOT NULL CHECK(revision>0),
 finding_id uuid GENERATED ALWAYS AS (CASE WHEN operation='finding' THEN target_id END) STORED,
 incident_id uuid GENERATED ALWAYS AS (CASE WHEN operation='incident' THEN target_id END) STORED,
 PRIMARY KEY(organization_id,operation,target_id),
 FOREIGN KEY(organization_id,finding_id) REFERENCES public.security_findings(organization_id,id),
 FOREIGN KEY(organization_id,incident_id) REFERENCES public.security_incidents(organization_id,id)
);
REVOKE ALL ON vader_private.triage_versions FROM PUBLIC,anon,authenticated,service_role,vader_ingest,vader_writer_owner;
GRANT SELECT,INSERT,UPDATE ON vader_private.triage_versions TO vader_triage_owner;
ALTER TABLE vader_private.triage_versions ENABLE ROW LEVEL SECURITY;
CREATE POLICY vader_human_version_scope ON vader_private.triage_versions TO vader_triage_owner
 USING(vader_private.human_guard_v1(organization_id,NULL) IS NOT NULL)
 WITH CHECK(vader_private.human_guard_v1(organization_id,NULL) IS NOT NULL);
'''
triage = change(triage, anchor, version_ddl + '\n' + anchor)
triage = change(triage, 'f public.security_findings; i public.security_incidents; fresh int;',
                'f public.security_findings; i public.security_incidents; current_revision bigint; fresh int;')
triage = change(triage, "IF request->>'expected_state' IS DISTINCT FROM", '''SELECT coalesce((SELECT v.revision FROM vader_private.triage_versions v
 WHERE v.organization_id=tenant AND v.operation=kind AND v.target_id=target),0) INTO current_revision;
 before_state:=before_state || jsonb_build_object('revision',current_revision);
 IF kind='incident' AND NOT (request ? 'assigned_to') AND i.assigned_to IS NOT NULL THEN
  PERFORM vader_private.human_guard_v1(tenant,i.assigned_to);
 END IF;
 IF request->>'expected_state' IS DISTINCT FROM''')
triage = change(triage, "IF before_state=after_state THEN", "IF (before_state-'revision')=after_state THEN")
triage = change(triage, ' INSERT INTO public.audit_logs(id,organization_id,actor_user_id,action,target_type,target_id,metadata)',
''' INSERT INTO vader_private.triage_versions(organization_id,operation,target_id,revision)
 VALUES(tenant,kind,target,current_revision+1)
 ON CONFLICT(organization_id,operation,target_id) DO UPDATE SET revision=EXCLUDED.revision;
 after_state:=after_state || jsonb_build_object('revision',current_revision+1);
 INSERT INTO public.audit_logs(id,organization_id,actor_user_id,action,target_type,target_id,metadata)''')
# Read token version in the same statement snapshot as the target row.
triage = change(triage, "'resolved_at',resolved_at)", "'resolved_at',resolved_at,'revision',coalesce((SELECT v.revision FROM vader_private.triage_versions v WHERE v.organization_id=tenant AND v.operation=kind AND v.target_id=target),0))", 2)
for name, sql in [('01_audit_permissions.sql', audit), ('02_reference_integrity.sql', reference),
                  ('03_machine_writer.sql', machine), ('04_human_triage.sql', triage)]:
    (HERE/name).write_text('-- Phase2 candidate; not executed.\n'+sql, encoding='utf8', newline='\n')
    # Runtime includes contain NO transaction terminators. Atomicity belongs to driver.
    clean = re.sub(r'^BEGIN;\s*$', '', sql, count=1, flags=re.M)
    clean = re.sub(r'^COMMIT;\s*$', '', clean, count=1, flags=re.M)
    (HERE/(name.replace('.sql', '.body.psql'))).write_text(clean, encoding='utf8', newline='\n')
(HERE/'source_hashes.json').write_text(json.dumps(inputs, indent=2)+'\n',encoding='utf8')
print('Phase2 candidates and transaction-free include bodies prepared offline.')
