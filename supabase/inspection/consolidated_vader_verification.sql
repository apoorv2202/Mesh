-- MESH / VADER: ONE read-only SELECT, ONE JSONB column: vader_verification.
-- Expected project: khweikfvsnervfuswhon (confirm dashboard; SQL does not prove it).
-- PostgreSQL 17. Run this ENTIRE file once in SQL Editor using role postgres.
-- No application/Auth rows, sequence values, credentials or connections queried.
-- No DDL/DML/DO/SET, helper execution, or test writes. No migrations are run.
-- To include the THREE requested public helper bodies, change false to true in
-- options below BEFORE running. Review output privately before sharing: bodies,
-- defaults, trigger arguments and expressions may contain embedded credentials.
-- Automatic redaction cannot reliably identify all secrets in arbitrary SQL.
-- Custom role-setting VALUES and unrelated routine bodies are never exported.
-- SQL SELECT cannot catch arbitrary permission/catalog/runtime errors per CTE.
-- Missing expected objects/roles are represented as diagnostics, not suppressed.
-- If the statement errors, return its SQLSTATE/message after credential review.

WITH
options AS (
 SELECT true AS include_helper_definitions
),
expected_roles(role_name) AS (
 VALUES ('anon'),('authenticated'),('service_role'),('authenticator'),('postgres'),
        ('vader_writer_owner'),('vader_ingest')
),
expected_tables(table_name) AS (
 VALUES ('security_events'),('security_findings'),('security_incidents'),
        ('incident_events'),('security_risk_scores')
),
role_inventory AS (
 SELECT oid,rolname,rolcanlogin,rolinherit,rolsuper,rolbypassrls,
        rolcreaterole,rolcreatedb,rolreplication,rolconnlimit
 FROM pg_catalog.pg_roles
),
focus_roles AS (
 SELECT r.* FROM role_inventory r
 WHERE r.rolname IN (SELECT role_name FROM expected_roles)
    OR r.rolname=current_user OR r.rolname=session_user
),
targets AS (
 SELECT c.oid,c.relname,c.relkind,c.relowner,c.relrowsecurity,c.relforcerowsecurity,
        c.relispartition,n.oid AS namespace_oid
 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relkind IN ('r','p','f')
   AND c.relname IN (SELECT table_name FROM expected_tables)
),
membership_edges AS (
 SELECT member.rolname AS member,granted.rolname AS granted_role,
        pg_catalog.pg_get_userbyid(m.grantor) AS grantor,
        m.admin_option,m.inherit_option,m.set_option
 FROM pg_catalog.pg_auth_members m
 JOIN role_inventory member ON member.oid=m.member
 JOIN role_inventory granted ON granted.oid=m.roleid
),
role_paths AS (
 SELECT a.rolname AS caller,b.rolname AS reachable_role,
        pg_catalog.pg_has_role(a.oid,b.oid,'MEMBER') AS member,
        pg_catalog.pg_has_role(a.oid,b.oid,'USAGE') AS inherits_now,
        pg_catalog.pg_has_role(a.oid,b.oid,'SET') AS can_set_role,
        b.rolsuper AS target_superuser,b.rolbypassrls AS target_bypassrls,
        b.rolcreaterole AS target_createrole,b.rolcreatedb AS target_createdb
 FROM focus_roles a CROSS JOIN role_inventory b
 WHERE a.oid<>b.oid AND pg_catalog.pg_has_role(a.oid,b.oid,'MEMBER')
),
schema_acl AS (
 SELECT n.nspname AS schema_name,pg_catalog.pg_get_userbyid(n.nspowner) AS owner,
        pg_catalog.pg_get_userbyid(a.grantor) AS grantor,
        CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END AS grantee,
        a.privilege_type,a.is_grantable,n.nspacl IS NULL AS acl_was_null
 FROM pg_catalog.pg_namespace n
 CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a
 WHERE n.nspname IN ('public','extensions','vader_private','vader_api')
),
schema_effective AS (
 SELECT r.rolname AS role_name,n.nspname AS schema_name,
        pg_catalog.has_schema_privilege(r.oid,n.oid,'USAGE') AS usage,
        pg_catalog.has_schema_privilege(r.oid,n.oid,'CREATE') AS create_objects
 FROM focus_roles r CROSS JOIN pg_catalog.pg_namespace n
 WHERE n.nspname IN ('public','extensions','vader_private','vader_api')
),
table_acl AS (
 SELECT t.relname AS table_name,pg_catalog.pg_get_userbyid(t.relowner) AS owner,
        pg_catalog.pg_get_userbyid(a.grantor) AS grantor,
        CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END AS grantee,
        a.privilege_type,a.is_grantable,t.oid AS table_oid
 FROM targets t
 CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(
   (SELECT relacl FROM pg_catalog.pg_class WHERE oid=t.oid),pg_catalog.acldefault('r',t.relowner))) a
),
table_effective AS (
 -- Included again for a consistent single-statement snapshot; no need to rerun
 -- the old first query separately. Effective ACL rights do not prove RLS access.
 SELECT r.rolname AS role_name,t.relname AS table_name,
        pg_catalog.has_schema_privilege(r.oid,t.namespace_oid,'USAGE') AS schema_usage,
        jsonb_object_agg(p.privilege,pg_catalog.has_table_privilege(r.oid,t.oid,p.privilege)
                         ORDER BY p.privilege) AS privileges
 FROM focus_roles r CROSS JOIN targets t
 CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),
                    ('REFERENCES'),('TRIGGER'),('MAINTAIN')) p(privilege)
 GROUP BY r.oid,r.rolname,t.oid,t.relname,t.namespace_oid
),
column_inventory AS (
 SELECT t.relname AS table_name,a.attrelid AS table_oid,a.attnum,a.attname AS column_name,
        pg_catalog.format_type(a.atttypid,a.atttypmod) AS data_type,
        a.attnotnull AS not_null,a.attidentity AS identity_kind,a.attgenerated AS generated_kind,
        pg_catalog.pg_get_expr(d.adbin,d.adrelid) AS default_or_generation_expression
 FROM targets t JOIN pg_catalog.pg_attribute a ON a.attrelid=t.oid
 LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
 WHERE a.attnum>0 AND NOT a.attisdropped
),
column_acl AS (
 SELECT c.table_name,c.column_name,pg_catalog.pg_get_userbyid(a.grantor) AS grantor,
        CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END AS grantee,
        a.privilege_type,a.is_grantable
 FROM column_inventory c JOIN pg_catalog.pg_attribute col
 ON col.attrelid=c.table_oid AND col.attnum=c.attnum
 CROSS JOIN LATERAL pg_catalog.aclexplode(col.attacl) a
),
column_effective AS (
 -- Includes table-level and inherited privileges even when column ACL is NULL.
 SELECT r.rolname AS role_name,c.table_name,c.column_name,c.attnum AS ordinal_position,
        jsonb_object_agg(p.privilege,
          pg_catalog.has_column_privilege(r.oid,c.table_oid,c.attnum,p.privilege)
          ORDER BY p.privilege) AS privileges
 FROM focus_roles r CROSS JOIN column_inventory c
 CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('REFERENCES')) p(privilege)
 GROUP BY r.oid,r.rolname,c.table_name,c.column_name,c.table_oid,c.attnum
),
default_acls AS (
 SELECT pg_catalog.pg_get_userbyid(d.defaclrole) AS creator,
        coalesce(n.nspname,'[global]') AS schema_name,d.defaclobjtype AS object_kind,
        pg_catalog.pg_get_userbyid(a.grantor) AS grantor,
        CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END AS grantee,
        a.privilege_type,a.is_grantable
 FROM pg_catalog.pg_default_acl d LEFT JOIN pg_catalog.pg_namespace n ON n.oid=d.defaclnamespace
 CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) a
 WHERE d.defaclnamespace=0 OR n.nspname IN ('public','extensions','vader_private','vader_api')
),
routine_targets AS (
 SELECT p.*,n.nspname AS schema_name
 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE (n.nspname='public' AND p.proname IN
       ('is_mesh_member','handle_new_mesh_user','rls_auto_enable'))
    OR (n.nspname='extensions' AND p.proname IN ('uuid_generate_v5','digest'))
    OR n.nspname IN ('vader_private','vader_api')
),
routines AS (
 SELECT p.oid AS routine_oid,p.schema_name,p.proname AS routine_name,
        p.oid::regprocedure::text AS identity,
        pg_catalog.pg_get_function_identity_arguments(p.oid) AS identity_arguments,
        pg_catalog.pg_get_function_result(p.oid) AS result_type,
        pg_catalog.pg_get_userbyid(p.proowner) AS owner,p.prokind,p.prosecdef,
        p.provolatile,p.proleakproof,p.proisstrict,l.lanname AS language,
        p.pronargs,p.pronargdefaults,
        coalesce((SELECT jsonb_agg(v ORDER BY v) FROM unnest(p.proconfig) v
         WHERE split_part(v,'=',1) IN ('search_path','row_security','TimeZone','timezone',
           'statement_timeout','lock_timeout','idle_in_transaction_session_timeout')),'[]'::jsonb) AS safety_settings,
        coalesce((SELECT jsonb_agg(split_part(v,'=',1) ORDER BY split_part(v,'=',1))
         FROM unnest(p.proconfig) v WHERE split_part(v,'=',1) NOT IN
         ('search_path','row_security','TimeZone','timezone','statement_timeout','lock_timeout',
          'idle_in_transaction_session_timeout')),'[]'::jsonb) AS other_setting_names_values_withheld,
        CASE
         WHEN p.schema_name<>'public' THEN 'not_requested'
         WHEN NOT o.include_helper_definitions THEN 'withheld_by_option'
         WHEN p.prokind NOT IN ('f','p') THEN 'unsupported_routine_kind'
         ELSE 'included_requires_private_secret_review' END AS definition_status,
        CASE WHEN o.include_helper_definitions AND p.schema_name='public' AND p.prokind IN ('f','p')
             THEN pg_catalog.pg_get_functiondef(p.oid) ELSE NULL END AS definition,
        CASE WHEN o.include_helper_definitions AND p.schema_name='public'
             THEN pg_catalog.pg_get_expr(p.proargdefaults,0) ELSE NULL END AS argument_defaults
 FROM routine_targets p JOIN pg_catalog.pg_language l ON l.oid=p.prolang CROSS JOIN options o
),
routine_acl AS (
 SELECT p.oid::regprocedure::text AS routine,pg_catalog.pg_get_userbyid(a.grantor) AS grantor,
        CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END AS grantee,
        a.privilege_type,a.is_grantable
 FROM routine_targets p CROSS JOIN LATERAL pg_catalog.aclexplode(
   coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
),
routine_effective AS (
 SELECT r.rolname AS role_name,p.oid::regprocedure::text AS routine,
        pg_catalog.has_schema_privilege(r.oid,p.pronamespace,'USAGE') AS schema_usage,
        pg_catalog.has_function_privilege(r.oid,p.oid,'EXECUTE') AS execute
 FROM focus_roles r CROSS JOIN routine_targets p
),
role_settings AS (
 -- Never export arbitrary values from pg_db_role_setting (may contain secrets).
 SELECT coalesce(r.rolname,'[all roles]') AS role_name,
        coalesce(d.datname,'[all databases]') AS database_name,
        coalesce((SELECT jsonb_agg(v ORDER BY v) FROM unnest(s.setconfig) v
         WHERE split_part(v,'=',1) IN ('search_path','row_security','TimeZone','timezone',
          'statement_timeout','lock_timeout','idle_in_transaction_session_timeout')),'[]'::jsonb) AS safety_settings,
        coalesce((SELECT jsonb_agg(split_part(v,'=',1) ORDER BY split_part(v,'=',1))
         FROM unnest(s.setconfig) v WHERE split_part(v,'=',1) NOT IN
         ('search_path','row_security','TimeZone','timezone','statement_timeout','lock_timeout',
          'idle_in_transaction_session_timeout')),'[]'::jsonb) AS other_setting_names_values_withheld
 FROM pg_catalog.pg_db_role_setting s LEFT JOIN role_inventory r ON r.oid=s.setrole
 LEFT JOIN pg_catalog.pg_database d ON d.oid=s.setdatabase
 WHERE (s.setrole=0 OR s.setrole IN (SELECT oid FROM focus_roles))
   AND (s.setdatabase=0 OR d.datname=current_database())
),
event_triggers AS (
 SELECT e.evtname,e.evtevent,e.evtenabled,e.evttags,
        pg_catalog.pg_get_userbyid(e.evtowner) AS owner,
        e.evtfoid::regprocedure::text AS handler
 FROM pg_catalog.pg_event_trigger e
),
row_triggers AS (
 SELECT n.nspname AS schema_name,c.relname AS table_name,t.tgname AS trigger_name,
        t.tgisinternal,t.tgenabled,pg_catalog.pg_get_triggerdef(t.oid,false) AS definition,
        t.tgfoid::regprocedure::text AS handler
 FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE t.tgrelid IN (SELECT oid FROM targets) OR t.tgfoid IN (SELECT oid FROM routine_targets)
),
sequence_targets AS (
 -- Dependencies discover identity/serial ownership without querying sequence
 -- rows or calling nextval/setval. An absent sequence becomes a missing list.
 SELECT DISTINCT s.oid,n.nspname,s.relname,s.relowner,s.relacl,d.deptype,
        t.relname AS table_name,a.attname AS column_name,
        ps.seqtypid::regtype::text AS data_type,ps.seqstart,ps.seqincrement,
        ps.seqmin,ps.seqmax,ps.seqcache,ps.seqcycle
 FROM targets t JOIN pg_catalog.pg_attribute a ON a.attrelid=t.oid
 JOIN pg_catalog.pg_depend d ON d.refclassid='pg_class'::regclass
   AND d.refobjid=t.oid AND d.refobjsubid=a.attnum
   AND d.classid='pg_class'::regclass AND d.deptype IN ('a','i')
 JOIN pg_catalog.pg_class s ON s.oid=d.objid AND s.relkind='S'
 JOIN pg_catalog.pg_namespace n ON n.oid=s.relnamespace
 JOIN pg_catalog.pg_sequence ps ON ps.seqrelid=s.oid
 WHERE a.attnum>0 AND NOT a.attisdropped
),
sequence_acl AS (
 SELECT s.nspname AS schema_name,s.relname AS sequence_name,
        pg_catalog.pg_get_userbyid(a.grantor) AS grantor,
        CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END AS grantee,
        a.privilege_type,a.is_grantable
 FROM sequence_targets s CROSS JOIN LATERAL pg_catalog.aclexplode(
   coalesce(s.relacl,pg_catalog.acldefault('s',s.relowner))) a
),
sequence_effective AS (
 SELECT r.rolname AS role_name,s.nspname AS schema_name,s.relname AS sequence_name,
        pg_catalog.has_schema_privilege(r.oid,s.nspname,'USAGE') AS schema_usage,
        pg_catalog.has_sequence_privilege(r.oid,s.oid,'USAGE') AS usage,
        pg_catalog.has_sequence_privilege(r.oid,s.oid,'SELECT') AS select_value,
        pg_catalog.has_sequence_privilege(r.oid,s.oid,'UPDATE') AS update_value
 FROM focus_roles r CROSS JOIN sequence_targets s
),
constraints AS (
 SELECT con.conname AS constraint_name,t.relname AS table_name,con.contype,
        con.convalidated,con.condeferrable,con.condeferred,
        pg_catalog.pg_get_constraintdef(con.oid,false) AS definition
 FROM targets t JOIN pg_catalog.pg_constraint con ON con.conrelid=t.oid
),
indexes AS (
 SELECT t.relname AS table_name,c.relname AS index_name,
        i.indisvalid,i.indisready,i.indisunique,i.indisprimary,
        pg_catalog.pg_get_indexdef(i.indexrelid) AS definition
 FROM targets t JOIN pg_catalog.pg_index i ON i.indrelid=t.oid
 JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
),
policies AS (
 SELECT t.relname AS table_name,p.polname,p.polcmd,p.polpermissive,
        (SELECT coalesce(jsonb_agg(CASE WHEN r=0 THEN 'PUBLIC'
                ELSE pg_catalog.pg_get_userbyid(r) END ORDER BY r),'[]'::jsonb)
         FROM unnest(p.polroles) r) AS roles,
        pg_catalog.pg_get_expr(p.polqual,p.polrelid) AS using_expression,
        pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid) AS with_check_expression
 FROM targets t JOIN pg_catalog.pg_policy p ON p.polrelid=t.oid
),
extensions AS (
 SELECT e.extname,e.extversion,n.nspname AS installed_schema,e.extrelocatable
 FROM pg_catalog.pg_extension e JOIN pg_catalog.pg_namespace n ON n.oid=e.extnamespace
 WHERE e.extname IN ('uuid-ossp','pgcrypto','plpgsql')
),
database_access AS (
 SELECT r.rolname AS role_name,
        pg_catalog.has_database_privilege(r.oid,d.oid,'CONNECT') AS connect,
        pg_catalog.has_database_privilege(r.oid,d.oid,'CREATE') AS create_schema,
        pg_catalog.has_database_privilege(r.oid,d.oid,'TEMP') AS temporary_objects
 FROM focus_roles r CROSS JOIN pg_catalog.pg_database d WHERE d.datname=current_database()
),
catalog_access AS (
 SELECT n.nspname||'.'||c.relname AS catalog,
        pg_catalog.has_table_privilege(current_user,c.oid,'SELECT') AS inspection_role_select
 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='pg_catalog' AND c.relname IN
 ('pg_roles','pg_auth_members','pg_class','pg_attribute','pg_namespace','pg_default_acl',
  'pg_proc','pg_db_role_setting','pg_event_trigger','pg_sequence','pg_depend','pg_policy')
)
SELECT jsonb_build_object(
 'metadata',jsonb_build_object(
   'captured_at',statement_timestamp(),'database',current_database(),
   'current_user',current_user,'session_user',session_user,
   'server_version',current_setting('server_version'),
   'server_version_num',current_setting('server_version_num'),
   'transaction_read_only',current_setting('transaction_read_only'),
   'session_search_path',current_setting('search_path'),
   'session_row_security',current_setting('row_security'),
   'helper_definitions_requested',(SELECT include_helper_definitions FROM options),
   'project_reference_sql_verified',false),
 'diagnostics',jsonb_build_object(
   'missing_expected_tables',(SELECT coalesce(jsonb_agg(table_name ORDER BY table_name),'[]'::jsonb)
      FROM expected_tables e WHERE NOT EXISTS(SELECT 1 FROM targets t WHERE t.relname=e.table_name)),
   'missing_existing_roles',(SELECT coalesce(jsonb_agg(role_name ORDER BY role_name),'[]'::jsonb)
      FROM expected_roles e WHERE role_name NOT IN ('vader_ingest','vader_writer_owner')
      AND NOT EXISTS(SELECT 1 FROM role_inventory r WHERE r.rolname=e.role_name)),
   'missing_proposed_roles_normal_before_migration',(SELECT coalesce(jsonb_agg(role_name ORDER BY role_name),'[]'::jsonb)
      FROM expected_roles e WHERE role_name IN ('vader_ingest','vader_writer_owner')
      AND NOT EXISTS(SELECT 1 FROM role_inventory r WHERE r.rolname=e.role_name)),
   'missing_helpers',(SELECT coalesce(jsonb_agg(name ORDER BY name),'[]'::jsonb)
      FROM (VALUES ('is_mesh_member'),('handle_new_mesh_user'),('rls_auto_enable')) e(name)
      WHERE NOT EXISTS(SELECT 1 FROM routine_targets p WHERE p.schema_name='public' AND p.proname=e.name)),
   'incident_identity_sequence_found',EXISTS(SELECT 1 FROM sequence_targets
       WHERE table_name='security_incidents' AND column_name='incident_number' AND deptype='i'),
   'uuid_v5_signature_found',EXISTS(SELECT 1 FROM routine_targets WHERE schema_name='extensions'
       AND proname='uuid_generate_v5' AND pg_catalog.oidvectortypes(proargtypes)='uuid, text'),
   'digest_signature_found',EXISTS(SELECT 1 FROM routine_targets WHERE schema_name='extensions'
       AND proname='digest' AND pg_catalog.oidvectortypes(proargtypes)='bytea, text'),
   'private_proposal_schema_collisions',(SELECT coalesce(jsonb_agg(nspname ORDER BY nspname),'[]'::jsonb)
       FROM pg_catalog.pg_namespace WHERE nspname IN ('vader_private','vader_api')),
   'catalog_access',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY catalog),'[]'::jsonb) FROM catalog_access c),
   'runtime_errors_caught',false,
   'error_handling','A plain SELECT cannot catch per-section SQL exceptions. Missing objects are diagnosed; permission, unsupported-version and runtime errors abort the statement. Return reviewed SQLSTATE/message if no JSON is produced.'),
 'roles',jsonb_build_object(
   'attributes',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY rolname),'[]'::jsonb) FROM role_inventory r),
   'membership_edges',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY member,granted_role),'[]'::jsonb) FROM membership_edges m),
   'effective_paths',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY caller,reachable_role),'[]'::jsonb) FROM role_paths p),
   'database_access',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY role_name),'[]'::jsonb) FROM database_access d),
   'safe_role_settings',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY role_name,database_name),'[]'::jsonb) FROM role_settings s)),
 'schemas',jsonb_build_object(
   'acls',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY schema_name,grantee,privilege_type),'[]'::jsonb) FROM schema_acl a),
   'effective',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY role_name,schema_name),'[]'::jsonb) FROM schema_effective e)),
 'tables',jsonb_build_object(
   'inventory',(SELECT coalesce(jsonb_agg(jsonb_build_object('table_name',relname,'relkind',relkind,
       'owner',pg_catalog.pg_get_userbyid(relowner),'rls_enabled',relrowsecurity,
       'rls_forced',relforcerowsecurity,'is_partition',relispartition) ORDER BY relname),'[]'::jsonb) FROM targets),
   'acls',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY table_name,grantee,privilege_type),'[]'::jsonb) FROM table_acl a),
   'effective',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY role_name,table_name),'[]'::jsonb) FROM table_effective e),
   'columns',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY table_name,attnum),'[]'::jsonb) FROM column_inventory c),
   'column_acls',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY table_name,column_name,grantee,privilege_type),'[]'::jsonb) FROM column_acl a),
   'column_effective',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY role_name,table_name,ordinal_position),'[]'::jsonb) FROM column_effective e),
   'constraints',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY table_name,constraint_name),'[]'::jsonb) FROM constraints c),
   'indexes',(SELECT coalesce(jsonb_agg(to_jsonb(i) ORDER BY table_name,index_name),'[]'::jsonb) FROM indexes i),
   'policies',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY table_name,polname),'[]'::jsonb) FROM policies p)),
 'default_acls',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY creator,schema_name,object_kind,grantee,privilege_type),'[]'::jsonb) FROM default_acls d),
 'functions',jsonb_build_object(
   'definitions_and_settings',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY schema_name,identity),'[]'::jsonb) FROM routines f),
   'acls',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY routine,grantee,privilege_type),'[]'::jsonb) FROM routine_acl a),
   'effective',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY role_name,routine),'[]'::jsonb) FROM routine_effective e)),
 'triggers',jsonb_build_object(
   'event',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY evtname),'[]'::jsonb) FROM event_triggers e),
   'row',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY schema_name,table_name,trigger_name),'[]'::jsonb) FROM row_triggers t)),
 'sequences',jsonb_build_object(
   'ownership_and_configuration',(SELECT coalesce(jsonb_agg((to_jsonb(s)-'relacl')||
       jsonb_build_object('owner',pg_catalog.pg_get_userbyid(relowner)) ORDER BY nspname,relname),'[]'::jsonb) FROM sequence_targets s),
   'acls',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY schema_name,sequence_name,grantee,privilege_type),'[]'::jsonb) FROM sequence_acl a),
   'effective',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY role_name,schema_name,sequence_name),'[]'::jsonb) FROM sequence_effective e)),
 'extensions',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY extname),'[]'::jsonb) FROM extensions e),
 'not_verified',jsonb_build_array(
   'Actual project reference or network endpoint from SQL alone; verify dashboard project.',
   'Custom-login authentication, TLS/network/IPv4/IPv6 reachability, pooler identity preservation or transaction pinning.',
   'CREATE ROLE, role-membership grants, ownership transfers or ALTER TABLE success under managed-platform restrictions; catalog attributes are evidence, not a capability test.',
   'Helper correctness: definitions require private review; helpers are not executed and impersonated-user/RLS tests are not run.',
   'Existing row duplicates, orphan/cross-tenant risk subjects, table volume or FK validation duration; no application rows are queried.',
   'Migration/function compilation, replay/idempotency, concurrency, rollback or generated-FK enforcement; require a disposable database.',
   'API exposed-schema configuration, frontend secret handling, secret rotation and uninspected alternate write paths.',
   'Secrets embedded in arbitrary definitions/defaults/trigger arguments; review output privately before sharing.'
 )
) AS vader_verification;
