-- Read-only TEST preflight; no application data or helper execution.
\set ON_ERROR_STOP on
\ir target_guard.psql
BEGIN READ ONLY;
-- First authenticated check, before the detailed catalog query. The verified
-- pooler route/username selects TEST; reject contradictory server identity.
SELECT current_user='postgres' AND session_user='postgres' AND current_database()='postgres'
 AND coalesce(nullif(current_setting('supabase.project_ref',true),''),'ikmzxirldivefebgxzaa')
     ='ikmzxirldivefebgxzaa' AS authenticated_identity_ok \gset
\if :authenticated_identity_ok
\else
ROLLBACK;
\echo Unexpected authenticated identity; detailed catalog inspection refused.
\quit 3
\endif
SELECT jsonb_build_object(
 'client_asserted_test_ref', :'vader_test_ref',
 'server_declared_project_ref',nullif(current_setting('supabase.project_ref',true),''),
 'server_project_ref_independently_verified',nullif(current_setting('supabase.project_ref',true),'')='ikmzxirldivefebgxzaa',
 'project_routing_basis','User-supplied TEST dashboard endpoint; verify-full TLS and exact postgres.ikmzxirldivefebgxzaa pooler username. A missing server project-ref setting is not independent SQL proof.',
 'database', current_database(),
 'database_owner',(SELECT pg_get_userbyid(datdba) FROM pg_catalog.pg_database WHERE datname=current_database()),
 'public_schema_owner',(SELECT pg_get_userbyid(nspowner) FROM pg_catalog.pg_namespace WHERE nspname='public'),
 'current_user', current_user, 'session_user', session_user,
 'server_version', current_setting('server_version'),
 'server_major_17', current_setting('server_version_num')::integer/10000=17,
 'transaction_read_only', current_setting('transaction_read_only'),
 'inspection_role',(SELECT jsonb_build_object('can_login',rolcanlogin,'superuser',rolsuper,
   'bypassrls',rolbypassrls,'createrole',rolcreaterole,'createdb',rolcreatedb)
   FROM pg_catalog.pg_roles WHERE rolname=current_user),
 'native_roles',(SELECT coalesce(jsonb_agg(rolname ORDER BY rolname),'[]'::jsonb)
   FROM pg_catalog.pg_roles WHERE rolname IN ('anon','authenticated','service_role','authenticator')),
 'auth_users_exists',to_regclass('auth.users') IS NOT NULL,
 'can_define_auth_user_trigger',CASE WHEN to_regclass('auth.users') IS NOT NULL
   THEN has_table_privilege(current_user,to_regclass('auth.users'),'TRIGGER') ELSE false END,
 'auth_uid_exists',to_regprocedure('auth.uid()') IS NOT NULL,
 'uuid_v5_available',to_regprocedure('extensions.uuid_generate_v5(uuid,text)') IS NOT NULL,
 'digest_available',to_regprocedure('extensions.digest(bytea,text)') IS NOT NULL,
 'installed_extensions',(SELECT coalesce(jsonb_agg(jsonb_build_object('name',e.extname,
   'version',e.extversion,'schema',n.nspname,'owner',pg_get_userbyid(e.extowner)) ORDER BY e.extname),'[]'::jsonb)
   FROM pg_catalog.pg_extension e JOIN pg_catalog.pg_namespace n ON n.oid=e.extnamespace),
 'schema_permissions',(SELECT coalesce(jsonb_agg(jsonb_build_object('schema',n.nspname,
   'owner',pg_get_userbyid(n.nspowner),'usage',has_schema_privilege(current_user,n.oid,'USAGE'),
   'create',has_schema_privilege(current_user,n.oid,'CREATE')) ORDER BY n.nspname),'[]'::jsonb)
   FROM pg_catalog.pg_namespace n WHERE n.nspname IN ('public','auth','extensions')),
 'required_function_permissions',(SELECT coalesce(jsonb_agg(jsonb_build_object(
   'routine',p.oid::regprocedure::text,'owner',pg_get_userbyid(p.proowner),
   'execute',has_function_privilege(current_user,p.oid,'EXECUTE')) ORDER BY p.oid::regprocedure::text),'[]'::jsonb)
   FROM pg_catalog.pg_proc p WHERE p.oid IN (
    to_regprocedure('auth.uid()'),to_regprocedure('extensions.uuid_generate_v5(uuid,text)'),
    to_regprocedure('extensions.digest(bytea,text)'))),
 'existing_public_tables',(SELECT coalesce(jsonb_agg(c.relname ORDER BY c.relname),'[]'::jsonb)
   FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='public' AND c.relkind IN ('r','p','f')),
 'application_object_conflicts',(SELECT coalesce(jsonb_agg(jsonb_build_object(
   'name',c.relname,'kind',c.relkind,'owner',pg_get_userbyid(c.relowner)) ORDER BY c.relname),'[]'::jsonb)
   FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='public' AND c.relname IN ('organizations','profiles','organization_members',
    'organization_invitations','audit_logs','cloud_integrations','security_assets','security_events',
    'security_findings','security_incidents','incident_events','security_risk_scores',
    'vader_detection_rules','vader_graph_nodes','vader_graph_edges','vader_response_actions',
    'vader_simulations','vader_trust_scores','security_incidents_incident_number_seq')),
 'enum_conflicts',(SELECT coalesce(jsonb_agg(t.typname ORDER BY t.typname),'[]'::jsonb)
   FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace
   WHERE n.nspname='public' AND t.typname IN ('mesh_role','mesh_member_status')),
 'proposal_schema_conflicts',(SELECT coalesce(jsonb_agg(nspname ORDER BY nspname),'[]'::jsonb)
   FROM pg_catalog.pg_namespace WHERE nspname IN ('vader_private','vader_api')),
 'proposal_role_conflicts',(SELECT coalesce(jsonb_agg(rolname ORDER BY rolname),'[]'::jsonb)
   FROM pg_catalog.pg_roles WHERE rolname IN ('vader_writer_owner','vader_ingest')),
 'existing_public_helpers',(SELECT coalesce(jsonb_agg(jsonb_build_object('name',p.proname,
   'owner',pg_get_userbyid(p.proowner),'security_definer',p.prosecdef,
   'definition_md5_cr_removed',md5(replace(pg_get_functiondef(p.oid),chr(13),''))) ORDER BY p.proname),'[]'::jsonb)
   FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
   WHERE n.nspname='public' AND p.proname IN ('is_mesh_member','handle_new_mesh_user','rls_auto_enable')),
 'existing_rls_event',(SELECT coalesce(jsonb_agg(jsonb_build_object('name',evtname,
   'event',evtevent,'enabled',evtenabled,'owner',pg_get_userbyid(evtowner),
   'handler',evtfoid::regprocedure::text,'tags',evttags)),'[]'::jsonb)
   FROM pg_catalog.pg_event_trigger WHERE evtname='ensure_rls'),
 'auth_trigger_conflicts',(SELECT coalesce(jsonb_agg(jsonb_build_object('name',t.tgname,
   'enabled',t.tgenabled,'internal',t.tgisinternal,'handler',t.tgfoid::regprocedure::text)),'[]'::jsonb)
   FROM pg_catalog.pg_trigger t WHERE t.tgrelid=to_regclass('auth.users') AND t.tgname='on_mesh_auth_user_created'),
 'native_role_memberships',(SELECT coalesce(jsonb_agg(jsonb_build_object(
   'member',mbr.rolname,'granted_role',gr.rolname,'inherit_option',m.inherit_option,
   'set_option',m.set_option,'admin_option',m.admin_option) ORDER BY mbr.rolname,gr.rolname),'[]'::jsonb)
   FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles mbr ON mbr.oid=m.member
   JOIN pg_catalog.pg_roles gr ON gr.oid=m.roleid
   WHERE mbr.rolname IN ('postgres','authenticator','anon','authenticated','service_role')),
 'api_schema_create',(SELECT coalesce(jsonb_agg(jsonb_build_object('role',rolname,
   'can_create_public',has_schema_privilege(oid,'public','CREATE')) ORDER BY rolname),'[]'::jsonb)
   FROM pg_catalog.pg_roles WHERE rolname IN ('anon','authenticated','service_role')),
 'limits',jsonb_build_array('Client routing and dashboard establish project selection; current_database alone does not.',
   'CREATE ROLE, ownership transfer and event-trigger creation are not tested by SELECT.',
   'No custom tenant-login authentication, FK validation or runtime isolation tested.')
) AS test_connection_check;
COMMIT;
