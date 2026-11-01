-- REVIEW-ONLY PROPOSAL. Outside migrations/ intentionally; DO NOT APPLY remotely.
-- PostgreSQL 17. Run only after privilege/helper review and disposable tests.
-- This file changes privileges only; it never rewrites helper function bodies.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

-- Stop accidental execution. An approved operator must explicitly set this
-- session GUC to 'on' after review; it is NOT an authorization mechanism.
DO $guard$
BEGIN
 IF current_setting('mesh_review.security_approved',true) IS DISTINCT FROM 'on' THEN
   RAISE EXCEPTION 'Review-only proposal: security review gate is closed';
 END IF;
END
$guard$;

-- Verified baseline: five postgres-owned RLS tables and no column ACL entries.
-- Do not let a missing object/role turn the postflight loops into a vacuous pass.
-- Drift requires review; no column-level grants or role memberships are guessed.
DO $baseline$
BEGIN
 IF current_setting('server_version_num')::integer / 10000 <> 17 THEN
  RAISE EXCEPTION 'Expected reviewed PostgreSQL 17 environment';
 END IF;
 IF (SELECT count(*) FROM pg_catalog.pg_roles
     WHERE rolname IN ('anon','authenticated','service_role'))<>3 THEN
  RAISE EXCEPTION 'Expected API role inventory changed';
 END IF;
 IF (SELECT count(*) FROM pg_catalog.pg_class c
     JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
     WHERE n.nspname='public' AND c.relkind='r' AND c.relrowsecurity
       AND pg_catalog.pg_get_userbyid(c.relowner)='postgres'
       AND c.relname IN ('security_events','security_findings','security_incidents',
                        'incident_events','security_risk_scores'))<>5 THEN
  RAISE EXCEPTION 'Expected VADER table ownership/RLS inventory changed';
 END IF;
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a
   JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
   JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
   WHERE n.nspname='public' AND a.attnum>0 AND NOT a.attisdropped
     AND c.relname IN ('security_events','security_findings','security_incidents',
                      'incident_events','security_risk_scores')) THEN
  RAISE EXCEPTION 'Column ACL drift requires review before table-level revocation';
 END IF;
END
$baseline$;

REVOKE TRUNCATE, REFERENCES, TRIGGER, MAINTAIN
ON TABLE public.security_events,public.security_findings,public.security_incidents,
         public.incident_events,public.security_risk_scores
FROM PUBLIC,anon,authenticated,service_role;

-- No frontend DML, even if an inherited grant has been added since the capture.
REVOKE INSERT,UPDATE,DELETE
ON TABLE public.security_events,public.security_findings,public.security_incidents,
         public.incident_events,public.security_risk_scores
FROM PUBLIC,anon,authenticated;

-- Deliberately DO NOT grant authenticated SELECT here. Active organization
-- membership/auth.uid behavior is user-confirmed; search_path, ownership and
-- runtime policy tests still need sign-off. A separate reviewed grant
-- can enable Security Team reads; persistence itself does not require it.
-- Do not grant table DML to service_role to work around RLS/ACL errors.

-- Fail closed if inherited/PUBLIC/ownership paths still supply dangerous powers.
-- These paths cannot be safely repaired by guessing broad membership revokes.
DO $audit$
DECLARE r record; t record; privilege text;
BEGIN
 FOR r IN SELECT oid,rolname FROM pg_roles
          WHERE rolname IN ('anon','authenticated','service_role') LOOP
  FOR t IN SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
           WHERE n.nspname='public' AND c.relname IN
           ('security_events','security_findings','security_incidents','incident_events','security_risk_scores') LOOP
   FOREACH privilege IN ARRAY ARRAY['TRUNCATE','REFERENCES','TRIGGER','MAINTAIN'] LOOP
    IF has_table_privilege(r.oid,t.oid,privilege) THEN
     RAISE EXCEPTION 'Residual dangerous privilege for role %; review membership/grant provenance',r.rolname;
    END IF;
   END LOOP;
   IF r.rolname IN ('anon','authenticated') AND
      (has_table_privilege(r.oid,t.oid,'INSERT') OR has_table_privilege(r.oid,t.oid,'UPDATE')
       OR has_table_privilege(r.oid,t.oid,'DELETE')) THEN
      RAISE EXCEPTION 'Residual frontend DML: membership review required';
   END IF;
  END LOOP;
 END LOOP;
END
$audit$;

-- Creator-specific default ACL changes affect ALL future public tables created
-- by that creator, not only VADER. Kept OUT of executable minimum on purpose.
-- Review separately for postgres AND supabase_admin, including global defaults.
-- A schema-scoped REVOKE cannot cancel a global default grant. Existing table
-- rights above are repaired independently; migration pipeline must check future
-- objects so broad creator defaults do not silently reintroduce these grants.
COMMIT;
