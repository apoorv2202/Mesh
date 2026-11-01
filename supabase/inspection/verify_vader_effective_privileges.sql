-- PROPOSAL: read-only follow-up. NOT executed by Codex.
-- Run only in an approved environment. No passwords, tokens, or application rows.
-- 1. Effective privileges include PUBLIC, ownership and inherited memberships.
WITH roles AS (
 SELECT oid, rolname, rolcanlogin, rolinherit, rolsuper, rolbypassrls,
        rolcreaterole, rolcreatedb FROM pg_roles
 WHERE rolname IN ('anon','authenticated','service_role','authenticator','postgres')
), targets AS (
 SELECT c.oid, c.relname, c.relowner FROM pg_class c
 JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname IN
 ('security_events','security_findings','security_incidents','incident_events','security_risk_scores')
)
SELECT r.*, t.relname, pg_get_userbyid(t.relowner) AS table_owner,
       has_schema_privilege(r.oid,'public','USAGE') AS schema_usage,
       has_schema_privilege(r.oid,'public','CREATE') AS schema_create,
       p.privilege, has_table_privilege(r.oid,t.oid,p.privilege) AS effective_privilege
FROM roles r CROSS JOIN targets t
CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),
                   ('REFERENCES'),('TRIGGER'),('MAINTAIN')) p(privilege)
ORDER BY r.rolname,t.relname,p.privilege;

-- 2. Transitive membership/SET paths (not just direct pg_auth_members edges).
SELECT a.rolname AS caller, b.rolname AS reachable_role,
       pg_has_role(a.oid,b.oid,'MEMBER') AS member,
       pg_has_role(a.oid,b.oid,'USAGE') AS inherits_now,
       pg_has_role(a.oid,b.oid,'SET') AS can_set_role,
       b.rolsuper, b.rolbypassrls
FROM pg_roles a CROSS JOIN pg_roles b
WHERE a.rolname IN ('anon','authenticated','service_role','authenticator')
  AND a.oid<>b.oid AND pg_has_role(a.oid,b.oid,'MEMBER')
ORDER BY caller,reachable_role;

-- 3. Edge options and grant provenance explain residual rights after REVOKE.
SELECT member.rolname AS member, granted.rolname AS granted_role,
       m.admin_option,m.inherit_option,m.set_option
FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member
JOIN pg_roles granted ON granted.oid=m.roleid ORDER BY member,granted_role;

-- 4. Public/table/column ACLs and exact creator-specific default ACLs.
SELECT n.nspname,c.relname,pg_get_userbyid(a.grantor) AS grantor,
       CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee,
       a.privilege_type,a.is_grantable
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
WHERE n.nspname='public' AND c.relname IN
 ('security_events','security_findings','security_incidents','incident_events','security_risk_scores')
ORDER BY c.relname,grantee,a.privilege_type;

SELECT pg_get_userbyid(d.defaclrole) AS creator,n.nspname,d.defaclobjtype,
       CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee,
       a.privilege_type,a.is_grantable
FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace
CROSS JOIN LATERAL aclexplode(d.defaclacl) a
WHERE n.nspname='public' OR d.defaclnamespace=0;

-- 5. Helpers: settings/defaults/ACL/owner only. No bodies or comments by default.
-- proconfig can hold custom secrets: output ONLY search_path and row_security.
SELECT p.oid::regprocedure::text AS routine,pg_get_userbyid(p.proowner) AS owner,
       p.prosecdef,p.provolatile,p.pronargdefaults,
       (SELECT jsonb_agg(setting) FROM unnest(p.proconfig) setting
        WHERE setting LIKE 'search_path=%' OR setting LIKE 'row_security=%') AS safety_settings,
       has_function_privilege('authenticated',p.oid,'EXECUTE') AS authenticated_execute,
       has_function_privilege('anon',p.oid,'EXECUTE') AS anon_execute
FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
WHERE n.nspname='public' AND p.proname IN
 ('is_mesh_member','handle_new_mesh_user','rls_auto_enable');

SELECT evtname,evtevent,evtenabled,evtfoid::regprocedure::text AS handler
FROM pg_event_trigger;

SELECT pg_get_serial_sequence('public.security_incidents','incident_number') AS identity_sequence;
-- Privately inspect pg_get_functiondef for the three helpers separately; bodies
-- were withheld in the saved export. Do not share embedded credential literals.
