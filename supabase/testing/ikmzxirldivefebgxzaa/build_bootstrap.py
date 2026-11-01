"""Offline generation only: no network, credentials, subprocesses or SQL execution."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
SUPABASE = HERE.parents[1]
EXPECTED = {
    "mesh_inspection.json": "0bb6b94031f1d0fe1fd843a20697ed49b4785b9c5e9696014e932c2b532d1fa4",
    "vader_verification.json": "70171889939c159a71704d0df4731738361d2a4c53a7d36e5880210b2554bc44",
}
TEST_PREFLIGHT_SHA256 = "b029522ac959950eccf9f61a5bc19be799e869f1e0df40175e458612c8dc5e72"


def qi(value):
    return '"' + value.replace('"', '""') + '"'


def qs(value):
    return "'" + value.replace("'", "''") + "'"


def literal(value, tag="mesh_source"):
    delimiter = f"${tag}$"
    assert delimiter not in value
    return delimiter + value + delimiter


def main():
    sources = {}
    for name, expected_hash in EXPECTED.items():
        raw = (SUPABASE / "inspection" / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected_hash, f"Source drift: {name}"
        sources[name] = json.loads(raw.decode("utf-8-sig"))
    old = sources["mesh_inspection.json"]
    new = sources["vader_verification.json"]
    preflight_bytes = (HERE / "preflight_result.json").read_bytes()
    assert hashlib.sha256(preflight_bytes).hexdigest() == TEST_PREFLIGHT_SHA256, "TEST preflight source drift"
    test = json.loads(preflight_bytes.decode("utf-8-sig"))
    assert test["client_asserted_test_ref"] == "ikmzxirldivefebgxzaa"
    assert test["server_version"] == "17.11" and test["transaction_read_only"] == "on"
    assert test["current_user"] == test["session_user"] == "postgres"
    assert test["auth_users_exists"] and test["auth_uid_exists"] and test["uuid_v5_available"] and test["digest_available"]
    for field in ["existing_public_tables", "application_object_conflicts", "enum_conflicts", "auth_trigger_conflicts", "proposal_role_conflicts", "proposal_schema_conflicts"]:
        assert test[field] == [], f"TEST conflict: {field}"
    tables = old["01_inventory"]["inspection"]["tables"]
    columns = old["02_columns"]["inspection"]
    constraints = old["03_constraints"]["inspection"]
    indexes = old["04_indexes"]["inspection"]
    policies = old["10_policies"]["inspection"]
    enums = old["05_enums"]["inspection"]
    grants = old["11_grants"]["inspection"]
    assert len(tables) == 18 and len(columns) == 165
    assert len(constraints) == 85 and len(indexes) == 46 and len(policies) == 18
    names = {t["relname"] for t in tables}
    assert all(t["owner"] == "postgres" and t["relkind"] == "r" for t in tables)
    assert all(c["schema_name"] == "public" for c in constraints)
    assert not any(c["generated_kind"] for c in columns)
    helper_records = [r for r in new["functions"]["definitions_and_settings"] if r["schema_name"] == "public"]
    assert {r["routine_name"] for r in helper_records} == {"is_mesh_member", "handle_new_mesh_user", "rls_auto_enable"}
    native_helper = next(h for h in helper_records if h["routine_name"] == "rls_auto_enable")
    native_hash = hashlib.md5(native_helper["definition"].replace("\r", "").encode()).hexdigest()
    assert test["existing_public_helpers"] == [{"name": "rls_auto_enable", "owner": "postgres", "security_definer": True, "definition_md5_cr_removed": native_hash}]
    assert len(test["existing_rls_event"]) == 1
    event = test["existing_rls_event"][0]
    assert event["name"] == "ensure_rls" and event["owner"] == "postgres" and event["enabled"] == "O"
    assert event["handler"] == "rls_auto_enable()" and event["event"] == "ddl_command_end"
    assert sorted(event["tags"]) == ["CREATE TABLE", "CREATE TABLE AS", "SELECT INTO"]
    seq = new["sequences"]["ownership_and_configuration"]
    assert len(seq) == 1 and seq[0]["relname"] == "security_incidents_incident_number_seq"
    seq = seq[0]
    assert seq["seqmax"] == 9223372036854776000  # damaged source, never emit this as SQL
    for key in ["seqstart", "seqincrement", "seqmin", "seqcache"]:
        assert seq[key] == 1
    assert seq["seqcycle"] is False and seq["data_type"] == "bigint"

    # The five newer definitions must agree with the earlier 18-table snapshot.
    oldcols = {(c["table_name"], c["column_name"]): c for c in columns}
    for c in new["tables"]["columns"]:
        prior = oldcols[c["table_name"], c["column_name"]]
        assert c["data_type"] == prior["postgres_type"]
        assert c["not_null"] is not prior["nullable"]
        assert c["default_or_generation_expression"] == prior["default_or_generation_expression"]
    out = [
        "-- GENERATED TEST FIXTURE ONLY; NOT A PRODUCTION MIGRATION OR IDENTICAL CLONE.",
        "-- Only approved endpoint: ikmzxirldivefebgxzaa. Use Invoke-TestDatabase.ps1.",
        "-- Intentionally reproduces dangerous baseline grants for migration 01 tests.",
        "-- No production data, passwords, role membership replay or migration history writes.",
        "-- Source hashes/fidelity exceptions: fidelity_manifest.json and README.md.",
        "\\set ON_ERROR_STOP on",
        "\\ir target_guard.psql",
        "\\if :{?vader_bootstrap_approved}",
        "\\else",
        "\\echo Bootstrap not approved; use the guarded launcher after human approval.",
        "\\quit 3",
        "\\endif",
        "SELECT :'vader_bootstrap_approved' = 'ikmzxirldivefebgxzaa' AS bootstrap_approved \\gset",
        "\\if :bootstrap_approved",
        "\\else",
        "\\echo Bootstrap approval target mismatch.",
        "\\quit 3",
        "\\endif",
        "BEGIN;",
        "SET LOCAL lock_timeout='5s';",
        "SET LOCAL statement_timeout='60s';",
        "SET LOCAL search_path=pg_catalog,public;",
        "SET LOCAL timezone='UTC';",
    ]
    table_list = ",".join(qs(n) for n in sorted(names))
    # Catalog-only preservation snapshot. No passwords, Auth rows or current
    # sequence values. Internal RI triggers created by new public FKs are excluded.
    native_snapshot = """SELECT jsonb_build_object(
 'schemas',(SELECT jsonb_agg(jsonb_build_object('name',nspname,'owner',nspowner,'acl',nspacl) ORDER BY nspname)
    FROM pg_catalog.pg_namespace WHERE nspname IN ('public','auth','extensions')),
 'routines',(SELECT jsonb_agg(jsonb_build_object('oid',p.oid,'owner',p.proowner,'acl',p.proacl,
    'definition_md5',md5(pg_get_functiondef(p.oid))) ORDER BY p.oid)
    FROM pg_catalog.pg_proc p WHERE p.oid IN (to_regprocedure('public.rls_auto_enable()'),
      to_regprocedure('auth.uid()'),to_regprocedure('extensions.uuid_generate_v5(uuid,text)'),
      to_regprocedure('extensions.digest(bytea,text)'))),
 'event_triggers',(SELECT jsonb_agg(to_jsonb(e) ORDER BY e.evtname) FROM pg_catalog.pg_event_trigger e),
 'memberships',(SELECT jsonb_agg(to_jsonb(m) ORDER BY m.roleid,m.member,m.grantor) FROM pg_catalog.pg_auth_members m),
 'role_attributes',(SELECT jsonb_agg(jsonb_build_object('oid',oid,'name',rolname,'super',rolsuper,
    'inherit',rolinherit,'createrole',rolcreaterole,'createdb',rolcreatedb,'login',rolcanlogin,
    'bypassrls',rolbypassrls,'replication',rolreplication) ORDER BY oid) FROM pg_catalog.pg_roles),
 'default_acls',(SELECT jsonb_agg(to_jsonb(d) ORDER BY d.oid) FROM pg_catalog.pg_default_acl d),
 'auth_users_acl',(SELECT jsonb_build_object('owner',relowner,'acl',relacl) FROM pg_catalog.pg_class WHERE oid='auth.users'::regclass),
 'auth_user_triggers',(SELECT jsonb_agg(jsonb_build_object('oid',t.oid,'name',t.tgname,
     'definition',pg_get_triggerdef(t.oid,false),'enabled',t.tgenabled) ORDER BY t.oid)
     FROM pg_catalog.pg_trigger t WHERE t.tgrelid='auth.users'::regclass AND NOT t.tgisinternal)
)"""
    out.append(f"""DO $preflight$
BEGIN
 IF current_user<>'postgres' OR session_user<>'postgres' THEN
  RAISE EXCEPTION 'TEST bootstrap requires the reviewed postgres connection';
 END IF;
 IF current_setting('server_version_num')::integer/10000<>17 THEN
  RAISE EXCEPTION 'Server must be PostgreSQL 17; client version is independent';
 END IF;
 IF (SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname IN ('anon','authenticated','service_role','authenticator'))<>4 THEN
  RAISE EXCEPTION 'Native Supabase roles missing';
 END IF;
 IF to_regclass('auth.users') IS NULL OR to_regprocedure('auth.uid()') IS NULL
    OR to_regprocedure('extensions.uuid_generate_v5(uuid,text)') IS NULL
    OR to_regprocedure('extensions.digest(bytea,text)') IS NULL THEN
  RAISE EXCEPTION 'Native Supabase/extension dependencies missing; do not invent them';
 END IF;
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='public' AND c.relname IN ({table_list},'security_incidents_incident_number_seq'))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace
   WHERE n.nspname='public' AND t.typname IN ('mesh_role','mesh_member_status'))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname IN ('vader_private','vader_api'))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname IN ('vader_writer_owner','vader_ingest')) THEN
  RAISE EXCEPTION 'TEST target is not a clean application fixture; nothing is overwritten';
 END IF;
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgname='on_mesh_auth_user_created'
   AND tgrelid='auth.users'::regclass) THEN
  RAISE EXCEPTION 'Existing application Auth trigger requires review';
 END IF;
 IF has_schema_privilege('anon','public','CREATE') OR has_schema_privilege('authenticated','public','CREATE')
    OR has_schema_privilege('service_role','public','CREATE') THEN
  RAISE EXCEPTION 'Unexpected API CREATE on public; review native schema ACL first';
 END IF;
 IF NOT has_schema_privilege(current_user,'public','CREATE')
    OR NOT has_schema_privilege(current_user,'public','USAGE')
    OR NOT has_schema_privilege(current_user,'auth','USAGE')
    OR NOT has_table_privilege(current_user,'auth.users','REFERENCES') THEN
  RAISE EXCEPTION 'Application creation/native Auth reference permission missing; no grants attempted';
 END IF;
 IF NOT has_schema_privilege('anon','public','USAGE')
    OR NOT has_schema_privilege('authenticated','public','USAGE')
    OR NOT has_schema_privilege('service_role','public','USAGE') THEN
  RAISE EXCEPTION 'Expected native public USAGE missing; schema ACL is preserved';
 END IF;
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname IN ('is_mesh_member','handle_new_mesh_user')) THEN
  RAISE EXCEPTION 'Application helper name already exists; no native helper replacement';
 END IF;
 IF to_regprocedure('public.rls_auto_enable()') IS NULL
    OR md5(replace(pg_get_functiondef(to_regprocedure('public.rls_auto_enable()')),chr(13),''))<>{qs(native_hash)}
    OR (SELECT pg_get_userbyid(proowner) FROM pg_catalog.pg_proc WHERE oid=to_regprocedure('public.rls_auto_enable()'))<>'postgres' THEN
  RAISE EXCEPTION 'Native RLS helper differs from verified TEST; verify/reuse only, no mutation';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_event_trigger e WHERE e.evtname='ensure_rls'
    AND e.evtevent='ddl_command_end' AND e.evtenabled='O'
    AND e.evtfoid=to_regprocedure('public.rls_auto_enable()') AND pg_get_userbyid(e.evtowner)='postgres'
    AND (SELECT array_agg(t ORDER BY t) FROM unnest(e.evttags) t)
      =ARRAY['CREATE TABLE','CREATE TABLE AS','SELECT INTO']::text[]) THEN
  RAISE EXCEPTION 'Native ensure_rls differs/missing; no CREATE or ALTER EVENT TRIGGER attempted';
 END IF;
 PERFORM set_config('mesh_test.native_snapshot',({native_snapshot})::text,true);
END
$preflight$;""")
    for enum in enums:
        assert enum["schema_name"] == "public"
        out.append(f"CREATE TYPE public.{qi(enum['enum_name'])} AS ENUM ({','.join(qs(v) for v in enum['labels'])});")
    for table in sorted(names):
        definitions = []
        for c in sorted((c for c in columns if c["table_name"] == table), key=lambda c: c["ordinal_position"]):
            t = c["postgres_type"]
            if c["udt_schema"] == "public":
                t = "public." + qi(c["udt_name"])
            part = f" {qi(c['column_name'])} {t}"
            if c["identity_kind"]:
                assert (table, c["column_name"], c["identity_kind"]) == ("security_incidents", "incident_number", "a")
                part += " GENERATED ALWAYS AS IDENTITY (SEQUENCE NAME public.security_incidents_incident_number_seq START WITH 1 INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 CACHE 1 NO CYCLE)"
            elif c["default_or_generation_expression"] is not None:
                part += " DEFAULT " + c["default_or_generation_expression"]
            if not c["nullable"]:
                part += " NOT NULL"
            definitions.append(part)
        out.append(f"CREATE TABLE public.{qi(table)} (\n" + ",\n".join(definitions) + "\n);")
    # Replay key constraints before FKs; all tables already exist (cycles allowed).
    for kind in ["p", "u", "c", "f"]:
        for c in sorted((c for c in constraints if c["constraint_type"] == kind), key=lambda c: (c["table_name"], c["constraint_name"])):
            out.append(f"ALTER TABLE public.{qi(c['table_name'])} ADD CONSTRAINT {qi(c['constraint_name'])} {c['definition']};")
    backed = {(c["table_name"], c["constraint_name"]) for c in constraints if c["constraint_type"] in {"p", "u"}}
    nonconstraint_indexes = []
    for idx in indexes:
        if (idx["table_name"], idx["index_name"]) not in backed:
            out.append(idx["definition"] + ";")
            nonconstraint_indexes.append(idx["index_name"])
    # rls_auto_enable is TEST-native: preflight verified it; never create, own or
    # change its ACL. Only create the two absent application helpers.
    for helper in helper_records:
        if helper["routine_name"] == "rls_auto_enable":
            continue
        definition = helper["definition"].replace("\r", "").rstrip().rstrip(";") + ";"
        assert "WITHHELD" not in definition and helper["owner"] == "postgres"
        definition = definition.replace("CREATE OR REPLACE FUNCTION", "CREATE FUNCTION", 1)
        signature = "public." + helper["routine_name"] + ("(uuid,public.mesh_role[])" if helper["routine_name"] == "is_mesh_member" else "()")
        out.append(definition)
        # New application functions are created as postgres by the identity guard.
        # No native helper owner transfer or ACL statements are emitted.
        out.append(f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC,anon,authenticated,service_role;")
        helper_acls = next(r["effective_acl"] for r in old["06_functions"]["inspection"] if r["schema_name"] == "public" and r["routine_name"] == helper["routine_name"])
        current_acls = [r for r in new["functions"]["acls"] if r["routine"] == helper["identity"]]
        assert {(a["grantee"], a["privilege"], a["grantable"]) for a in helper_acls} == {(a["grantee"], a["privilege_type"], a["is_grantable"]) for a in current_acls}
        for acl in helper_acls:
            target = "PUBLIC" if acl["grantee"] == "PUBLIC" else qi(acl["grantee"])
            out.append(f"GRANT EXECUTE ON FUNCTION {signature} TO {target}" + (" WITH GRANT OPTION" if acl["grantable"] else "") + ";")
    for table in old["09_rls_status"]["inspection"]:
        assert table["rls_enabled"] is True and table["rls_forced"] is False
        out.append(f"ALTER TABLE public.{qi(table['table_name'])} ENABLE ROW LEVEL SECURITY;")
    for policy in policies:
        roles = ",".join("PUBLIC" if r == "PUBLIC" else qi(r) for r in policy["roles"])
        text = f"CREATE POLICY {qi(policy['policy_name'])} ON public.{qi(policy['table_name'])} AS {'PERMISSIVE' if policy['permissive'] else 'RESTRICTIVE'} FOR {policy['command']} TO {roles}"
        if policy["using_expression"] is not None:
            text += " USING (" + policy["using_expression"] + ")"
        if policy["with_check_expression"] is not None:
            text += " WITH CHECK (" + policy["with_check_expression"] + ")"
        out.append(text + ";")
    # Current-object parity only. Preserve native roles, schema ownership and
    # creator-wide defaults; differences are explicitly recorded in the manifest.
    for table in sorted(names):
        out.append(f"REVOKE ALL ON TABLE public.{qi(table)} FROM PUBLIC,anon,authenticated,service_role;")
        grouped = {}
        for grant in grants:
            if grant["object_kind"] == "relation" and grant["object_name"] == table:
                assert grant["grantor"] == "postgres" and grant["grantee"] in {"postgres", "anon", "authenticated", "service_role"}
                grouped.setdefault((grant["grantee"], grant["is_grantable"]), []).append(grant["privilege_type"])
        for (grantee, grantable), privileges in sorted(grouped.items()):
            out.append(f"GRANT {','.join(sorted(privileges))} ON TABLE public.{qi(table)} TO {qi(grantee)}" + (" WITH GRANT OPTION" if grantable else "") + ";")
    out.append("REVOKE ALL ON SEQUENCE public.security_incidents_incident_number_seq FROM PUBLIC,anon,authenticated,service_role;")
    for grant in new["sequences"]["acls"]:
        assert grant["sequence_name"] == "security_incidents_incident_number_seq" and grant["grantor"] == "postgres"
        out.append(f"GRANT {grant['privilege_type']} ON SEQUENCE public.security_incidents_incident_number_seq TO {qi(grant['grantee'])}" + (" WITH GRANT OPTION" if grant["is_grantable"] else "") + ";")
    # Deliberately omit the application Auth-user trigger. No explicit DDL targets
    # auth.users. FK-generated internal RI triggers are still necessary/preserved.
    out.append(f"""DO $postflight$
DECLARE table_oids oid[];
BEGIN
 SELECT array_agg(c.oid) INTO table_oids FROM pg_catalog.pg_class c
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname IN ({table_list});
 IF cardinality(table_oids)<>18
 OR (SELECT count(*) FROM pg_catalog.pg_attribute WHERE attrelid=ANY(table_oids) AND attnum>0 AND NOT attisdropped)<>165
 OR (SELECT count(*) FROM pg_catalog.pg_constraint WHERE conrelid=ANY(table_oids))<>85
 OR (SELECT count(*) FROM pg_catalog.pg_index WHERE indrelid=ANY(table_oids))<>46
 OR (SELECT count(*) FROM pg_catalog.pg_policy WHERE polrelid=ANY(table_oids))<>18
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=ANY(table_oids)
    AND (NOT relrowsecurity OR relforcerowsecurity OR pg_get_userbyid(relowner)<>'postgres')) THEN
  RAISE EXCEPTION 'TEST reconstruction postflight mismatch; transaction aborted';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_sequence s JOIN pg_catalog.pg_class c ON c.oid=s.seqrelid
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname='security_incidents_incident_number_seq'
     AND pg_get_userbyid(c.relowner)='postgres' AND s.seqmax=9223372036854775807
     AND s.seqstart=1 AND s.seqincrement=1 AND s.seqmin=1 AND s.seqcache=1 AND NOT s.seqcycle) THEN
  RAISE EXCEPTION 'TEST identity sequence mismatch';
 END IF;
 IF ({native_snapshot}) IS DISTINCT FROM current_setting('mesh_test.native_snapshot')::jsonb THEN
  RAISE EXCEPTION 'Native roles/ACLs/functions/events/Auth application triggers changed; transaction aborted';
 END IF;
END
$postflight$;""")
    out += ["-- No application data or synthetic Auth users are loaded by this schema file.", "COMMIT;"]
    bootstrap = "\n\n".join(out) + "\n"
    assert "9223372036854776000" not in bootstrap
    (HERE / "bootstrap_test_only.sql").write_text(bootstrap, encoding="utf-8", newline="\n")
    manifest = {
        "purpose": "Disposable TEST reconstruction, not an identical production clone or production migration",
        "allowed_test_ref": "ikmzxirldivefebgxzaa",
        "blocked_production_ref": "khweikfvsnervfuswhon",
        "source_sha256": EXPECTED,
        "test_preflight_sha256": TEST_PREFLIGHT_SHA256,
        "verified_test": {"server": test["server_version"], "database": test["database"], "user": test["current_user"], "read_only_capture": test["transaction_read_only"], "superuser": test["inspection_role"]["superuser"], "schema_create_public": next(s["create"] for s in test["schema_permissions"] if s["schema"] == "public")},
        "source_capture_times": [old["01_inventory"]["inspection"]["captured_at"], new["metadata"]["captured_at"]],
        "helper_definition_md5_cr_removed": {
            h["routine_name"]: hashlib.md5(h["definition"].replace("\r", "").encode()).hexdigest()
            for h in helper_records
        },
        "bootstrap_sha256": hashlib.sha256(bootstrap.encode()).hexdigest(),
        "expected": {"application_tables": 18, "columns": 165, "constraints": 85, "indexes": 46, "policies": 18, "enums": 2, "public_helpers": 3, "application_helpers_created": 2, "native_helpers_reused": 1, "custom_auth_user_trigger_created": 0, "native_event_triggers_created_or_altered": 0, "native_ensure_rls_reused": 1, "application_rows_loaded": 0},
        "constraint_counts": dict(Counter(c["constraint_type"] for c in constraints)),
        "nonconstraint_indexes_emitted": nonconstraint_indexes,
        "sequence_exception": {"source_invalid_max": str(seq["seqmax"]), "test_max": "9223372036854775807", "reason": "PostgreSQL bigint type maximum; exact source value lost in JSON export", "verified_production_max": False},
        "intentional_limits": [
            "No managed schema, Auth records, database login roles or membership relationships copied",
            "No creator-wide default ACL changes; current application objects get captured explicit ACLs",
            "No original script order/comments, physical storage settings, current sequence counter or data recovered",
            "Two offline captures; five-table definitions agree, not an atomic whole-database snapshot",
            "Native rls_auto_enable and ensure_rls are verified/reused without CREATE/ALTER/GRANT/REVOKE on them",
            "Auth-user provisioning trigger omitted: synthetic profiles need explicit TEST seeding; automatic Auth-to-profile provisioning is not covered",
            "No public/auth/extensions schema ACL changes; native roles/ACLs/functions/events/defaults/noninternal Auth triggers are compared before/after",
            "Application FKs to native auth.users still generate internal referential-integrity triggers/dependencies; not a zero-catalog-change clone",
            "Actual DDL/function compilation and REFERENCES authority are guarded runtime checks; custom-login/writer ownership tests remain later work",
        ],
    }
    (HERE / "fidelity_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("Generated TEST-only bootstrap and fidelity manifest; no SQL executed.")


if __name__ == "__main__":
    main()
