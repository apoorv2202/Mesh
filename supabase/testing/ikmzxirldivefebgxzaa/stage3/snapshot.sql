-- Metadata only. Called inside the driver's transaction. Produces one JSON value.
WITH targets AS (
 SELECT c.oid,c.relname,c.relowner,c.relacl,c.relrowsecurity,c.relforcerowsecurity
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relkind='r' AND c.relname IN
 ('security_events','security_findings','security_incidents','incident_events','security_risk_scores')
), roles AS (
 SELECT oid,rolname FROM pg_roles WHERE rolname IN ('anon','authenticated','authenticator','service_role','postgres')
), effective AS (
 SELECT r.rolname,t.relname,p.privilege,
 has_table_privilege(r.oid,t.oid,p.privilege) AS allowed
 FROM targets t CROSS JOIN roles r CROSS JOIN unnest(
 ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN']) p(privilege)
)
SELECT jsonb_build_object(
 'effective',(SELECT jsonb_agg(to_jsonb(e) ORDER BY rolname,relname,privilege) FROM effective e),
 'target_acls',(SELECT jsonb_agg(jsonb_build_object('table',relname,'owner',relowner,'acl',relacl) ORDER BY relname) FROM targets),
 'column_acls',(SELECT jsonb_agg(jsonb_build_object('table',t.relname,'column',a.attname,'acl',a.attacl) ORDER BY t.relname,a.attnum)
 FROM targets t JOIN pg_attribute a ON a.attrelid=t.oid WHERE a.attnum>0 AND NOT a.attisdropped AND a.attacl IS NOT NULL),
 'native',jsonb_build_object(
 'roles',(SELECT jsonb_agg(jsonb_build_object('oid',oid,'name',rolname,'super',rolsuper,'inherit',rolinherit,
 'login',rolcanlogin,'bypass',rolbypassrls,'createrole',rolcreaterole,'createdb',rolcreatedb,'replication',rolreplication) ORDER BY oid) FROM pg_roles),
 'memberships',(SELECT jsonb_agg(to_jsonb(m) ORDER BY roleid,member,grantor) FROM pg_auth_members m),
 'schemas',(SELECT jsonb_agg(jsonb_build_object('oid',oid,'owner',nspowner,'acl',nspacl) ORDER BY oid) FROM pg_namespace),
 'functions',(SELECT jsonb_agg(jsonb_build_object('oid',p.oid,'owner',proowner,'acl',proacl,'settings_md5',md5(proconfig::text),
 'definition_md5',CASE WHEN prokind IN ('f','p') THEN md5(pg_get_functiondef(p.oid)) ELSE NULL END) ORDER BY p.oid) FROM pg_proc p),
 'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY oid) FROM pg_event_trigger e),
 'defaults',(SELECT jsonb_agg(to_jsonb(d) ORDER BY oid) FROM pg_default_acl d),
 'relations',(SELECT jsonb_agg(jsonb_build_object('oid',c.oid,'owner',relowner,'acl',relacl,'rls',relrowsecurity,'forced',relforcerowsecurity) ORDER BY c.oid)
 FROM pg_class c WHERE c.oid NOT IN (SELECT oid FROM targets)),
 'sequences',(SELECT jsonb_agg(to_jsonb(s) ORDER BY seqrelid) FROM pg_sequence s),
 'policies',(SELECT jsonb_agg(to_jsonb(p) ORDER BY oid) FROM pg_policy p),
 'constraints',(SELECT jsonb_agg(to_jsonb(c) ORDER BY oid) FROM pg_constraint c),
 'indexes',(SELECT jsonb_agg(to_jsonb(i) ORDER BY indexrelid) FROM pg_index i),
 'triggers',(SELECT jsonb_agg(jsonb_build_object('oid',oid,'row_md5',md5(to_jsonb(t)::text)) ORDER BY oid) FROM pg_trigger t),
 'target_rls',(SELECT jsonb_agg(jsonb_build_object('table',relname,'owner',relowner,'enabled',relrowsecurity,'forced',relforcerowsecurity) ORDER BY relname) FROM targets)
 )) AS snapshot
\gset
