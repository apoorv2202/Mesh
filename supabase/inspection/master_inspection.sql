-- MESH master schema inspection: one read-only statement, one row, one JSONB column.
-- Target project: khweikfvsnervfuswhon. Paste this ENTIRE file into SQL Editor
-- and Run once. Copy/export the mesh_inspection cell; check for UI truncation.
-- Each key retains ALL columns of its original section result, including
-- inspection and (where present) section. Original payloads and empty arrays
-- are preserved without flattening or renaming their fields.
-- Section 07 bodies remain WITHHELD by default. Its local options CTE below
-- controls include_sensitive_definitions; leave false for routine inspection.
-- Catalog metadata only: no application/auth rows or credential stores queried.
-- Definitions (defaults, checks, triggers, policies) can contain embedded SQL
-- literals: review privately and redact any credentials before sharing results.
-- No automatic filter can guarantee arbitrary catalog text contains no secrets.
-- No remote execution was performed while generating this file.
-- This is metadata evidence, not a restorable migration or a complete dependency
-- audit. pg_depend cannot discover dynamic SQL / all string-body references.
-- Permissions affect visibility; all sections share this statement's snapshot.

WITH
section_01 AS (
  WITH expected(name) AS (VALUES
   ('organizations'), ('profiles'), ('organization_members'),
   ('organization_invitations'), ('audit_logs'), ('cloud_integrations'),
   ('security_assets'), ('security_events'), ('security_findings'),
   ('security_incidents'), ('incident_events'), ('security_risk_scores'),
   ('vader_detection_rules'), ('vader_graph_nodes'), ('vader_graph_edges'),
   ('vader_response_actions'), ('vader_simulations'), ('vader_trust_scores')
  ), actual AS (
   SELECT c.oid, c.relname, c.relkind, c.relispartition,
          pg_get_userbyid(c.relowner) AS owner,
          EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass
                  AND d.objid = c.oid AND d.deptype = 'e') AS extension_owned
   FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'f')
  )
  SELECT jsonb_build_object(
   'section', '01_inventory', 'captured_at', statement_timestamp(),
   'database', current_database(), 'server_version', current_setting('server_version'),
   'inspection_role', current_user, 'expected_count', (SELECT count(*) FROM expected),
   'actual_count_including_partition_children', (SELECT count(*) FROM actual),
   'tables', (SELECT coalesce(jsonb_agg(to_jsonb(a) - 'oid' ORDER BY relname), '[]'::jsonb) FROM actual a),
   'missing_expected', (SELECT coalesce(jsonb_agg(name ORDER BY name), '[]'::jsonb)
                        FROM expected WHERE NOT EXISTS (SELECT 1 FROM actual WHERE relname = name)),
   'unexpected_tables', (SELECT coalesce(jsonb_agg(relname ORDER BY relname), '[]'::jsonb)
                        FROM actual WHERE NOT EXISTS (SELECT 1 FROM expected WHERE name = relname))
  ) AS inspection
),

section_02 AS (
  WITH rows AS (
   SELECT n.nspname AS schema_name, c.relname AS table_name,
          a.attnum AS ordinal_position, a.attname AS column_name,
          format_type(a.atttypid, a.atttypmod) AS postgres_type,
          NOT a.attnotnull AS nullable,
          pg_get_expr(ad.adbin, ad.adrelid) AS default_or_generation_expression,
          a.attidentity AS identity_kind, a.attgenerated AS generated_kind,
          cn.nspname AS collation_schema, coll.collname AS collation_name,
          ic.data_type, ic.udt_schema, ic.udt_name, ic.domain_schema, ic.domain_name,
          ic.character_maximum_length, ic.numeric_precision, ic.numeric_scale,
          ic.datetime_precision, ic.is_identity, ic.identity_generation
   FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
   JOIN pg_namespace n ON n.oid = c.relnamespace
   LEFT JOIN pg_attrdef ad ON ad.adrelid = c.oid AND ad.adnum = a.attnum
   LEFT JOIN pg_collation coll ON coll.oid = a.attcollation
   LEFT JOIN pg_namespace cn ON cn.oid = coll.collnamespace
   LEFT JOIN information_schema.columns ic
     ON ic.table_schema = n.nspname AND ic.table_name = c.relname AND ic.column_name = a.attname
   WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'f')
     AND a.attnum > 0 AND NOT a.attisdropped
  )
  SELECT '02_columns' AS section,
   coalesce(jsonb_agg(to_jsonb(rows) ORDER BY table_name, ordinal_position), '[]'::jsonb) AS inspection FROM rows
),

section_03 AS (
  WITH rows AS (
   SELECT n.nspname AS schema_name, c.relname AS table_name, con.conname AS constraint_name,
          con.contype AS constraint_type, pg_get_constraintdef(con.oid, false) AS definition,
          con.convalidated AS validated, con.condeferrable AS deferrable,
          con.condeferred AS initially_deferred,
          rn.nspname AS referenced_schema, rc.relname AS referenced_table,
          con.confupdtype AS update_action_code, con.confdeltype AS delete_action_code
   FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid
   JOIN pg_namespace n ON n.oid = c.relnamespace
   LEFT JOIN pg_class rc ON rc.oid = con.confrelid
   LEFT JOIN pg_namespace rn ON rn.oid = rc.relnamespace
   WHERE n.nspname = 'public' OR rn.nspname = 'public'
  )
  SELECT '03_constraints' AS section,
   coalesce(jsonb_agg(to_jsonb(rows) ORDER BY schema_name, table_name, constraint_name), '[]'::jsonb) AS inspection FROM rows
),

section_04 AS (
  WITH rows AS (
   SELECT t.relname AS table_name, i.relname AS index_name,
          pg_get_indexdef(i.oid) AS definition,
          x.indisprimary AS is_primary, x.indisunique AS is_unique,
          x.indisvalid AS is_valid, x.indisready AS is_ready,
          pg_get_expr(x.indpred, x.indrelid) AS predicate
   FROM pg_index x JOIN pg_class t ON t.oid = x.indrelid
   JOIN pg_namespace n ON n.oid = t.relnamespace JOIN pg_class i ON i.oid = x.indexrelid
   WHERE n.nspname = 'public'
  )
  SELECT '04_indexes' AS section,
   coalesce(jsonb_agg(to_jsonb(rows) ORDER BY table_name, index_name), '[]'::jsonb) AS inspection FROM rows
),

section_05 AS (
  WITH RECURSIVE used_types(oid) AS (
   SELECT DISTINCT a.atttypid FROM pg_attribute a
   JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relkind IN ('r','p','f') AND a.attnum > 0 AND NOT a.attisdropped
   UNION
   SELECT d.refobjid FROM pg_depend d JOIN used_types u ON u.oid = d.objid
   WHERE d.classid = 'pg_type'::regclass AND d.refclassid = 'pg_type'::regclass
  ), rows AS (
   SELECT n.nspname AS schema_name, t.typname AS enum_name,
          (SELECT jsonb_agg(e.enumlabel ORDER BY e.enumsortorder) FROM pg_enum e WHERE e.enumtypid = t.oid) AS labels
   FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
   WHERE t.typtype = 'e' AND (n.nspname = 'public' OR t.oid IN (SELECT oid FROM used_types))
  )
  SELECT '05_enums' AS section,
   coalesce(jsonb_agg(to_jsonb(rows) ORDER BY schema_name, enum_name), '[]'::jsonb) AS inspection FROM rows
),

section_06 AS (
  WITH routine_ids AS (
   SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public'
   UNION
   SELECT d.refobjid FROM pg_depend d
   WHERE d.refclassid = 'pg_proc'::regclass
     AND (EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                  WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND n.nspname = 'public')
       OR EXISTS (SELECT 1 FROM pg_attrdef a JOIN pg_class c ON c.oid = a.adrelid JOIN pg_namespace n ON n.oid = c.relnamespace
                  WHERE d.classid = 'pg_attrdef'::regclass AND d.objid = a.oid AND n.nspname = 'public')
       OR EXISTS (SELECT 1 FROM pg_policy x JOIN pg_class c ON c.oid = x.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
                  WHERE d.classid = 'pg_policy'::regclass AND d.objid = x.oid AND n.nspname = 'public')
       OR EXISTS (SELECT 1 FROM pg_rewrite x JOIN pg_class c ON c.oid = x.ev_class JOIN pg_namespace n ON n.oid = c.relnamespace
                  WHERE d.classid = 'pg_rewrite'::regclass AND d.objid = x.oid AND n.nspname = 'public'))
   UNION
   SELECT t.tgfoid FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
   JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public'
  ), rows AS (
   SELECT n.nspname AS schema_name, p.proname AS routine_name,
          pg_get_function_identity_arguments(p.oid) AS identity_arguments,
          pg_get_function_result(p.oid) AS result_type, p.prokind AS routine_kind,
          l.lanname AS language, pg_get_userbyid(p.proowner) AS owner,
          p.prosecdef AS security_definer, p.provolatile AS volatility,
          p.proleakproof AS leakproof, p.proisstrict AS strict,
          p.proconfig IS NOT NULL AS has_routine_settings,
          (SELECT coalesce(jsonb_agg(jsonb_build_object(
            'grantor', pg_get_userbyid(a.grantor),
            'grantee', CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
            'privilege', a.privilege_type, 'grantable', a.is_grantable)), '[]'::jsonb)
           FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a) AS effective_acl
   FROM pg_proc p JOIN routine_ids r ON r.oid = p.oid
   JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_language l ON l.oid = p.prolang
  )
  SELECT '06_routine_inventory' AS section,
   coalesce(jsonb_agg(to_jsonb(rows) ORDER BY schema_name, routine_name, identity_arguments), '[]'::jsonb) AS inspection FROM rows
),

section_07 AS (
  WITH options AS (SELECT false AS include_sensitive_definitions), rows AS (
   SELECT n.nspname AS schema_name, p.proname AS routine_name,
          pg_get_function_identity_arguments(p.oid) AS identity_arguments,
          CASE WHEN o.include_sensitive_definitions THEN pg_get_functiondef(p.oid)
               ELSE '[WITHHELD: enable section 07 only for private review]' END AS definition
   FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace CROSS JOIN options o
   WHERE n.nspname = 'public' AND p.prokind IN ('f', 'p')
  )
  SELECT '07_routine_definitions' AS section,
   coalesce(jsonb_agg(to_jsonb(rows) ORDER BY routine_name, identity_arguments), '[]'::jsonb) AS inspection FROM rows
),

section_08 AS (
  WITH rows AS (
   SELECT n.nspname AS schema_name, c.relname AS table_name, t.tgname AS trigger_name,
          t.tgisinternal AS internal, t.tgenabled AS enabled_mode,
          pn.nspname AS function_schema, p.proname AS function_name,
          pg_get_function_identity_arguments(p.oid) AS function_identity_arguments,
          pg_get_triggerdef(t.oid, false) AS definition
   FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
   JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_proc p ON p.oid = t.tgfoid
   JOIN pg_namespace pn ON pn.oid = p.pronamespace
   WHERE n.nspname = 'public' OR pn.nspname = 'public'
  )
  SELECT '08_triggers' AS section,
   coalesce(jsonb_agg(to_jsonb(rows) ORDER BY schema_name, table_name, trigger_name), '[]'::jsonb) AS inspection FROM rows
),

section_09 AS (
  WITH rows AS (
   SELECT c.relname AS table_name, pg_get_userbyid(c.relowner) AS owner,
          c.relrowsecurity AS rls_enabled, c.relforcerowsecurity AS rls_forced,
          (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid) AS policy_count
   FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'f')
  )
  SELECT '09_rls_status' AS section,
   coalesce(jsonb_agg(to_jsonb(rows) ORDER BY table_name), '[]'::jsonb) AS inspection FROM rows
),

section_10 AS (
  WITH rows AS (
   SELECT c.relname AS table_name, p.polname AS policy_name,
          CASE p.polcmd WHEN '*' THEN 'ALL' WHEN 'r' THEN 'SELECT' WHEN 'a' THEN 'INSERT'
               WHEN 'w' THEN 'UPDATE' WHEN 'd' THEN 'DELETE' END AS command,
          p.polpermissive AS permissive,
          (SELECT jsonb_agg(CASE WHEN r = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(r) END ORDER BY r)
           FROM unnest(p.polroles) r) AS roles,
          pg_get_expr(p.polqual, p.polrelid) AS using_expression,
          pg_get_expr(p.polwithcheck, p.polrelid) AS with_check_expression
   FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
   JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public'
  )
  SELECT '10_rls_policies' AS section,
   coalesce(jsonb_agg(to_jsonb(rows) ORDER BY table_name, policy_name), '[]'::jsonb) AS inspection FROM rows
),

section_11 AS (
  WITH grants AS (
   SELECT 'schema'::text AS object_kind, n.nspname AS schema_name, n.nspname AS object_name,
          NULL::text AS column_name, a.grantor, a.grantee, a.privilege_type, a.is_grantable
   FROM pg_namespace n CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) a
   WHERE n.nspname = 'public'
   UNION ALL
   SELECT CASE WHEN c.relkind = 'S' THEN 'sequence' ELSE 'relation' END,
          n.nspname, c.relname, NULL::text, a.grantor, a.grantee, a.privilege_type, a.is_grantable
   FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   CROSS JOIN LATERAL aclexplode(coalesce(c.relacl, acldefault(CASE WHEN c.relkind = 'S' THEN 's'::"char" ELSE 'r'::"char" END, c.relowner))) a
   WHERE n.nspname = 'public' AND c.relkind IN ('r','p','f','v','m','S')
   UNION ALL
   SELECT 'column', n.nspname, c.relname, col.attname, a.grantor, a.grantee, a.privilege_type, a.is_grantable
   FROM pg_attribute col JOIN pg_class c ON c.oid = col.attrelid
   JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN LATERAL aclexplode(col.attacl) a
   WHERE n.nspname = 'public' AND col.attnum > 0 AND NOT col.attisdropped
   UNION ALL
   SELECT 'default_acl:' || d.defaclobjtype::text, coalesce(n.nspname, '[all schemas]'),
          pg_get_userbyid(d.defaclrole), NULL::text, a.grantor, a.grantee, a.privilege_type, a.is_grantable
   FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
   CROSS JOIN LATERAL aclexplode(d.defaclacl) a
   WHERE n.nspname = 'public' OR d.defaclnamespace = 0
  ), rows AS (
   SELECT object_kind, schema_name, object_name, column_name,
          pg_get_userbyid(grantor) AS grantor,
          CASE WHEN grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(grantee) END AS grantee,
          privilege_type, is_grantable FROM grants
  )
  SELECT '11_grants' AS section,
   coalesce(jsonb_agg(to_jsonb(rows) ORDER BY object_kind, object_name, column_name, grantee, privilege_type), '[]'::jsonb) AS inspection FROM rows
),

section_12 AS (
  WITH dependencies AS (
   SELECT d.deptype, x.type AS dependent_type, x.schema AS dependent_schema,
          x.identity AS dependent_identity, y.type AS referenced_type,
          y.schema AS referenced_schema, y.identity AS referenced_identity
   FROM pg_depend d
   CROSS JOIN LATERAL pg_identify_object(d.classid, d.objid, d.objsubid) x
   CROSS JOIN LATERAL pg_identify_object(d.refclassid, d.refobjid, d.refobjsubid) y
   WHERE (x.schema = 'public' AND y.schema IS DISTINCT FROM 'public')
      OR (y.schema = 'public' AND x.schema IS DISTINCT FROM 'public')
  ), extensions AS (
   SELECT e.extname AS extension_name, e.extversion AS version, n.nspname AS installed_schema,
          e.extrelocatable AS relocatable
   FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
  )
  SELECT '12_extensions_dependencies' AS section,
   jsonb_build_object(
     'installed_extensions', (SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY extension_name), '[]'::jsonb) FROM extensions e),
     'cross_schema_dependencies', (SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY dependent_identity, referenced_identity, deptype), '[]'::jsonb) FROM dependencies d)
   ) AS inspection
)
SELECT jsonb_build_object(
  '01_inventory', (SELECT to_jsonb(s) FROM section_01 AS s),
  '02_columns', (SELECT to_jsonb(s) FROM section_02 AS s),
  '03_constraints', (SELECT to_jsonb(s) FROM section_03 AS s),
  '04_indexes', (SELECT to_jsonb(s) FROM section_04 AS s),
  '05_enums', (SELECT to_jsonb(s) FROM section_05 AS s),
  '06_functions', (SELECT to_jsonb(s) FROM section_06 AS s),
  '07_function_definitions', (SELECT to_jsonb(s) FROM section_07 AS s),
  '08_triggers', (SELECT to_jsonb(s) FROM section_08 AS s),
  '09_rls_status', (SELECT to_jsonb(s) FROM section_09 AS s),
  '10_policies', (SELECT to_jsonb(s) FROM section_10 AS s),
  '11_grants', (SELECT to_jsonb(s) FROM section_11 AS s),
  '12_extensions_dependencies', (SELECT to_jsonb(s) FROM section_12 AS s)
) AS mesh_inspection;
