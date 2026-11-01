-- GENERATED TEST FIXTURE ONLY; NOT A PRODUCTION MIGRATION OR IDENTICAL CLONE.

-- Only approved endpoint: ikmzxirldivefebgxzaa. Use Invoke-TestDatabase.ps1.

-- Intentionally reproduces dangerous baseline grants for migration 01 tests.

-- No production data, passwords, role membership replay or migration history writes.

-- Source hashes/fidelity exceptions: fidelity_manifest.json and README.md.

\set ON_ERROR_STOP on

\ir target_guard.psql

\if :{?vader_bootstrap_approved}

\else

\echo Bootstrap not approved; use the guarded launcher after human approval.

\quit 3

\endif

SELECT :'vader_bootstrap_approved' = 'ikmzxirldivefebgxzaa' AS bootstrap_approved \gset

\if :bootstrap_approved

\else

\echo Bootstrap approval target mismatch.

\quit 3

\endif

BEGIN;

SET LOCAL lock_timeout='5s';

SET LOCAL statement_timeout='60s';

SET LOCAL search_path=pg_catalog,public;

SET LOCAL timezone='UTC';

DO $preflight$
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
   WHERE n.nspname='public' AND c.relname IN ('audit_logs','cloud_integrations','incident_events','organization_invitations','organization_members','organizations','profiles','security_assets','security_events','security_findings','security_incidents','security_risk_scores','vader_detection_rules','vader_graph_edges','vader_graph_nodes','vader_response_actions','vader_simulations','vader_trust_scores','security_incidents_incident_number_seq'))
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
    OR md5(replace(pg_get_functiondef(to_regprocedure('public.rls_auto_enable()')),chr(13),''))<>'846ec2fbff751d24b890656d63c3a9bf'
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
 PERFORM set_config('mesh_test.native_snapshot',(SELECT jsonb_build_object(
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
))::text,true);
END
$preflight$;

CREATE TYPE public."mesh_member_status" AS ENUM ('pending','active','suspended','offboarded');

CREATE TYPE public."mesh_role" AS ENUM ('owner','hr','senior_developer','junior_developer','security_team');

CREATE TABLE public."audit_logs" (
 "id" uuid DEFAULT gen_random_uuid() NOT NULL,
 "organization_id" uuid NOT NULL,
 "actor_user_id" uuid,
 "action" text NOT NULL,
 "target_type" text,
 "target_id" text,
 "metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
 "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public."cloud_integrations" (
 "id" uuid DEFAULT gen_random_uuid() NOT NULL,
 "organization_id" uuid NOT NULL,
 "provider" text NOT NULL,
 "display_name" text NOT NULL,
 "external_account_id" text,
 "status" text DEFAULT 'disconnected'::text NOT NULL,
 "configuration" jsonb DEFAULT '{}'::jsonb NOT NULL,
 "last_sync_at" timestamp with time zone,
 "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public."incident_events" (
 "organization_id" uuid NOT NULL,
 "incident_id" uuid NOT NULL,
 "event_id" uuid NOT NULL,
 "relationship" text DEFAULT 'related'::text NOT NULL,
 "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public."organization_invitations" (
 "id" uuid DEFAULT gen_random_uuid() NOT NULL,
 "organization_id" uuid NOT NULL,
 "email" text NOT NULL,
 "full_name" text,
 "employee_id" text,
 "role" public."mesh_role" NOT NULL,
 "status" text DEFAULT 'pending'::text NOT NULL,
 "expires_at" timestamp with time zone NOT NULL,
 "invited_by" uuid,
 "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public."organization_members" (
 "id" uuid DEFAULT gen_random_uuid() NOT NULL,
 "organization_id" uuid NOT NULL,
 "user_id" uuid NOT NULL,
 "employee_id" text,
 "role" public."mesh_role" NOT NULL,
 "status" public."mesh_member_status" DEFAULT 'pending'::mesh_member_status NOT NULL,
 "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public."organizations" (
 "id" uuid DEFAULT gen_random_uuid() NOT NULL,
 "name" text NOT NULL,
 "domain" text,
 "domain_verified_at" timestamp with time zone,
 "status" text DEFAULT 'onboarding'::text NOT NULL,
 "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public."profiles" (
 "id" uuid NOT NULL,
 "full_name" text,
 "avatar_url" text,
 "timezone" text DEFAULT 'UTC'::text NOT NULL,
 "created_at" timestamp with time zone DEFAULT now() NOT NULL,
 "updated_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public."security_assets" (
 "id" uuid DEFAULT gen_random_uuid() NOT NULL,
 "organization_id" uuid NOT NULL,
 "integration_id" uuid,
 "external_resource_id" text,
 "name" text NOT NULL,
 "asset_type" text NOT NULL,
 "provider" text DEFAULT 'mesh'::text NOT NULL,
 "environment" text,
 "criticality" text DEFAULT 'medium'::text NOT NULL,
 "metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
 "last_seen_at" timestamp with time zone,
 "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public."security_events" (
 "id" uuid DEFAULT gen_random_uuid() NOT NULL,
 "organization_id" uuid NOT NULL,
 "asset_id" uuid,
 "source" text NOT NULL,
 "external_event_id" text,
 "event_type" text NOT NULL,
 "actor_user_id" uuid,
 "actor_identifier" text,
 "action" text,
 "outcome" text,
 "source_ip" inet,
 "severity" text DEFAULT 'info'::text NOT NULL,
 "event_time" timestamp with time zone NOT NULL,
 "received_at" timestamp with time zone DEFAULT now() NOT NULL,
 "details" jsonb DEFAULT '{}'::jsonb NOT NULL
);

CREATE TABLE public."security_findings" (
 "id" uuid DEFAULT gen_random_uuid() NOT NULL,
 "organization_id" uuid NOT NULL,
 "asset_id" uuid,
 "source_event_id" uuid,
 "title" text NOT NULL,
 "description" text,
 "finding_type" text NOT NULL,
 "severity" text DEFAULT 'medium'::text NOT NULL,
 "status" text DEFAULT 'open'::text NOT NULL,
 "evidence" jsonb DEFAULT '{}'::jsonb NOT NULL,
 "remediation" text,
 "detected_at" timestamp with time zone DEFAULT now() NOT NULL,
 "resolved_at" timestamp with time zone
);

CREATE TABLE public."security_incidents" (
 "id" uuid DEFAULT gen_random_uuid() NOT NULL,
 "organization_id" uuid NOT NULL,
 "incident_number" bigint GENERATED ALWAYS AS IDENTITY (SEQUENCE NAME public.security_incidents_incident_number_seq START WITH 1 INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 CACHE 1 NO CYCLE) NOT NULL,
 "title" text NOT NULL,
 "description" text,
 "severity" text DEFAULT 'medium'::text NOT NULL,
 "status" text DEFAULT 'detected'::text NOT NULL,
 "risk_score" numeric(5,2),
 "confidence" numeric(4,3),
 "assigned_to" uuid,
 "summary" jsonb DEFAULT '{}'::jsonb NOT NULL,
 "detected_at" timestamp with time zone DEFAULT now() NOT NULL,
 "resolved_at" timestamp with time zone,
 "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public."security_risk_scores" (
 "id" uuid DEFAULT gen_random_uuid() NOT NULL,
 "organization_id" uuid NOT NULL,
 "subject_type" text NOT NULL,
 "subject_id" uuid NOT NULL,
 "score" numeric(5,2) NOT NULL,
 "confidence" numeric(4,3),
 "factors" jsonb DEFAULT '{}'::jsonb NOT NULL,
 "explanation" text,
 "model_version" text NOT NULL,
 "calculated_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public."vader_detection_rules" (
 "id" uuid DEFAULT gen_random_uuid() NOT NULL,
 "organization_id" uuid NOT NULL,
 "rule_code" text NOT NULL,
 "name" text NOT NULL,
 "description" text,
 "event_type" text NOT NULL,
 "severity" text NOT NULL,
 "conditions" jsonb DEFAULT '{}'::jsonb NOT NULL,
 "enabled" boolean DEFAULT true NOT NULL,
 "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public."vader_graph_edges" (
 "id" uuid DEFAULT gen_random_uuid() NOT NULL,
 "organization_id" uuid NOT NULL,
 "source_node_id" uuid NOT NULL,
 "target_node_id" uuid NOT NULL,
 "relationship" text NOT NULL,
 "properties" jsonb DEFAULT '{}'::jsonb NOT NULL,
 "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public."vader_graph_nodes" (
 "id" uuid DEFAULT gen_random_uuid() NOT NULL,
 "organization_id" uuid NOT NULL,
 "node_type" text NOT NULL,
 "external_id" text,
 "label" text NOT NULL,
 "properties" jsonb DEFAULT '{}'::jsonb NOT NULL,
 "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public."vader_response_actions" (
 "id" uuid DEFAULT gen_random_uuid() NOT NULL,
 "organization_id" uuid NOT NULL,
 "incident_id" uuid NOT NULL,
 "action_type" text NOT NULL,
 "proposed_by" uuid,
 "approved_by" uuid,
 "status" text DEFAULT 'proposed'::text NOT NULL,
 "justification" text,
 "execution_result" jsonb,
 "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public."vader_simulations" (
 "id" uuid DEFAULT gen_random_uuid() NOT NULL,
 "organization_id" uuid NOT NULL,
 "name" text NOT NULL,
 "simulation_type" text NOT NULL,
 "input_data" jsonb DEFAULT '{}'::jsonb NOT NULL,
 "output_data" jsonb,
 "status" text DEFAULT 'pending'::text NOT NULL,
 "created_by" uuid,
 "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public."vader_trust_scores" (
 "id" uuid DEFAULT gen_random_uuid() NOT NULL,
 "organization_id" uuid NOT NULL,
 "user_id" uuid NOT NULL,
 "score" numeric(5,2) NOT NULL,
 "stars" numeric(2,1) NOT NULL,
 "factors" jsonb DEFAULT '{}'::jsonb NOT NULL,
 "calculated_at" timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE public."audit_logs" ADD CONSTRAINT "audit_logs_pkey" PRIMARY KEY (id);

ALTER TABLE public."cloud_integrations" ADD CONSTRAINT "cloud_integrations_pkey" PRIMARY KEY (id);

ALTER TABLE public."incident_events" ADD CONSTRAINT "incident_events_pkey" PRIMARY KEY (incident_id, event_id);

ALTER TABLE public."organization_invitations" ADD CONSTRAINT "organization_invitations_pkey" PRIMARY KEY (id);

ALTER TABLE public."organization_members" ADD CONSTRAINT "organization_members_pkey" PRIMARY KEY (id);

ALTER TABLE public."organizations" ADD CONSTRAINT "organizations_pkey" PRIMARY KEY (id);

ALTER TABLE public."profiles" ADD CONSTRAINT "profiles_pkey" PRIMARY KEY (id);

ALTER TABLE public."security_assets" ADD CONSTRAINT "security_assets_pkey" PRIMARY KEY (id);

ALTER TABLE public."security_events" ADD CONSTRAINT "security_events_pkey" PRIMARY KEY (id);

ALTER TABLE public."security_findings" ADD CONSTRAINT "security_findings_pkey" PRIMARY KEY (id);

ALTER TABLE public."security_incidents" ADD CONSTRAINT "security_incidents_pkey" PRIMARY KEY (id);

ALTER TABLE public."security_risk_scores" ADD CONSTRAINT "security_risk_scores_pkey" PRIMARY KEY (id);

ALTER TABLE public."vader_detection_rules" ADD CONSTRAINT "vader_detection_rules_pkey" PRIMARY KEY (id);

ALTER TABLE public."vader_graph_edges" ADD CONSTRAINT "vader_graph_edges_pkey" PRIMARY KEY (id);

ALTER TABLE public."vader_graph_nodes" ADD CONSTRAINT "vader_graph_nodes_pkey" PRIMARY KEY (id);

ALTER TABLE public."vader_response_actions" ADD CONSTRAINT "vader_response_actions_pkey" PRIMARY KEY (id);

ALTER TABLE public."vader_simulations" ADD CONSTRAINT "vader_simulations_pkey" PRIMARY KEY (id);

ALTER TABLE public."vader_trust_scores" ADD CONSTRAINT "vader_trust_scores_pkey" PRIMARY KEY (id);

ALTER TABLE public."cloud_integrations" ADD CONSTRAINT "cloud_integrations_organization_id_id_key" UNIQUE (organization_id, id);

ALTER TABLE public."organization_members" ADD CONSTRAINT "organization_members_organization_id_employee_id_key" UNIQUE (organization_id, employee_id);

ALTER TABLE public."organization_members" ADD CONSTRAINT "organization_members_organization_id_user_id_key" UNIQUE (organization_id, user_id);

ALTER TABLE public."security_assets" ADD CONSTRAINT "security_assets_organization_id_id_key" UNIQUE (organization_id, id);

ALTER TABLE public."security_events" ADD CONSTRAINT "security_events_organization_id_id_key" UNIQUE (organization_id, id);

ALTER TABLE public."security_findings" ADD CONSTRAINT "security_findings_organization_id_id_key" UNIQUE (organization_id, id);

ALTER TABLE public."security_incidents" ADD CONSTRAINT "security_incidents_incident_number_key" UNIQUE (incident_number);

ALTER TABLE public."security_incidents" ADD CONSTRAINT "security_incidents_organization_id_id_key" UNIQUE (organization_id, id);

ALTER TABLE public."vader_detection_rules" ADD CONSTRAINT "vader_detection_rules_organization_id_id_key" UNIQUE (organization_id, id);

ALTER TABLE public."vader_detection_rules" ADD CONSTRAINT "vader_detection_rules_organization_id_rule_code_key" UNIQUE (organization_id, rule_code);

ALTER TABLE public."vader_graph_nodes" ADD CONSTRAINT "vader_graph_nodes_organization_id_id_key" UNIQUE (organization_id, id);

ALTER TABLE public."cloud_integrations" ADD CONSTRAINT "cloud_integrations_provider_check" CHECK ((provider = ANY (ARRAY['azure'::text, 'aws'::text, 'gcp'::text])));

ALTER TABLE public."cloud_integrations" ADD CONSTRAINT "cloud_integrations_status_check" CHECK ((status = ANY (ARRAY['disconnected'::text, 'pending'::text, 'connected'::text, 'error'::text])));

ALTER TABLE public."organization_invitations" ADD CONSTRAINT "organization_invitations_status_check" CHECK ((status = ANY (ARRAY['pending'::text, 'accepted'::text, 'expired'::text, 'revoked'::text])));

ALTER TABLE public."organizations" ADD CONSTRAINT "organizations_status_check" CHECK ((status = ANY (ARRAY['onboarding'::text, 'active'::text, 'suspended'::text])));

ALTER TABLE public."security_assets" ADD CONSTRAINT "security_assets_criticality_check" CHECK ((criticality = ANY (ARRAY['low'::text, 'medium'::text, 'high'::text, 'critical'::text])));

ALTER TABLE public."security_events" ADD CONSTRAINT "security_events_severity_check" CHECK ((severity = ANY (ARRAY['info'::text, 'low'::text, 'medium'::text, 'high'::text, 'critical'::text])));

ALTER TABLE public."security_findings" ADD CONSTRAINT "security_findings_severity_check" CHECK ((severity = ANY (ARRAY['info'::text, 'low'::text, 'medium'::text, 'high'::text, 'critical'::text])));

ALTER TABLE public."security_findings" ADD CONSTRAINT "security_findings_status_check" CHECK ((status = ANY (ARRAY['open'::text, 'investigating'::text, 'remediating'::text, 'resolved'::text, 'false_positive'::text, 'accepted_risk'::text])));

ALTER TABLE public."security_incidents" ADD CONSTRAINT "security_incidents_confidence_check" CHECK (((confidence >= (0)::numeric) AND (confidence <= (1)::numeric)));

ALTER TABLE public."security_incidents" ADD CONSTRAINT "security_incidents_risk_score_check" CHECK (((risk_score >= (0)::numeric) AND (risk_score <= (100)::numeric)));

ALTER TABLE public."security_incidents" ADD CONSTRAINT "security_incidents_severity_check" CHECK ((severity = ANY (ARRAY['low'::text, 'medium'::text, 'high'::text, 'critical'::text])));

ALTER TABLE public."security_incidents" ADD CONSTRAINT "security_incidents_status_check" CHECK ((status = ANY (ARRAY['detected'::text, 'triaged'::text, 'investigating'::text, 'contained'::text, 'remediating'::text, 'recovering'::text, 'resolved'::text, 'false_positive'::text])));

ALTER TABLE public."security_risk_scores" ADD CONSTRAINT "security_risk_scores_confidence_check" CHECK (((confidence >= (0)::numeric) AND (confidence <= (1)::numeric)));

ALTER TABLE public."security_risk_scores" ADD CONSTRAINT "security_risk_scores_score_check" CHECK (((score >= (0)::numeric) AND (score <= (100)::numeric)));

ALTER TABLE public."security_risk_scores" ADD CONSTRAINT "security_risk_scores_subject_type_check" CHECK ((subject_type = ANY (ARRAY['identity'::text, 'asset'::text, 'finding'::text, 'incident'::text])));

ALTER TABLE public."vader_detection_rules" ADD CONSTRAINT "vader_detection_rules_severity_check" CHECK ((severity = ANY (ARRAY['low'::text, 'medium'::text, 'high'::text, 'critical'::text])));

ALTER TABLE public."vader_response_actions" ADD CONSTRAINT "vader_response_actions_status_check" CHECK ((status = ANY (ARRAY['proposed'::text, 'approved'::text, 'rejected'::text, 'executing'::text, 'completed'::text, 'failed'::text])));

ALTER TABLE public."vader_simulations" ADD CONSTRAINT "vader_simulations_simulation_type_check" CHECK ((simulation_type = ANY (ARRAY['what_if'::text, 'attack_replay'::text])));

ALTER TABLE public."vader_simulations" ADD CONSTRAINT "vader_simulations_status_check" CHECK ((status = ANY (ARRAY['pending'::text, 'running'::text, 'completed'::text, 'failed'::text])));

ALTER TABLE public."vader_trust_scores" ADD CONSTRAINT "vader_trust_scores_score_check" CHECK (((score >= (0)::numeric) AND (score <= (100)::numeric)));

ALTER TABLE public."vader_trust_scores" ADD CONSTRAINT "vader_trust_scores_stars_check" CHECK (((stars >= (0)::numeric) AND (stars <= (5)::numeric)));

ALTER TABLE public."audit_logs" ADD CONSTRAINT "audit_logs_actor_user_id_fkey" FOREIGN KEY (actor_user_id) REFERENCES auth.users(id);

ALTER TABLE public."audit_logs" ADD CONSTRAINT "audit_logs_organization_id_fkey" FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE;

ALTER TABLE public."cloud_integrations" ADD CONSTRAINT "cloud_integrations_organization_id_fkey" FOREIGN KEY (organization_id) REFERENCES organizations(id);

ALTER TABLE public."incident_events" ADD CONSTRAINT "incident_events_organization_id_event_id_fkey" FOREIGN KEY (organization_id, event_id) REFERENCES security_events(organization_id, id);

ALTER TABLE public."incident_events" ADD CONSTRAINT "incident_events_organization_id_fkey" FOREIGN KEY (organization_id) REFERENCES organizations(id);

ALTER TABLE public."incident_events" ADD CONSTRAINT "incident_events_organization_id_incident_id_fkey" FOREIGN KEY (organization_id, incident_id) REFERENCES security_incidents(organization_id, id) ON DELETE CASCADE;

ALTER TABLE public."organization_invitations" ADD CONSTRAINT "organization_invitations_invited_by_fkey" FOREIGN KEY (invited_by) REFERENCES auth.users(id);

ALTER TABLE public."organization_invitations" ADD CONSTRAINT "organization_invitations_organization_id_fkey" FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE;

ALTER TABLE public."organization_members" ADD CONSTRAINT "organization_members_organization_id_fkey" FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE;

ALTER TABLE public."organization_members" ADD CONSTRAINT "organization_members_user_id_fkey" FOREIGN KEY (user_id) REFERENCES profiles(id) ON DELETE CASCADE;

ALTER TABLE public."profiles" ADD CONSTRAINT "profiles_id_fkey" FOREIGN KEY (id) REFERENCES auth.users(id) ON DELETE CASCADE;

ALTER TABLE public."security_assets" ADD CONSTRAINT "security_assets_organization_id_fkey" FOREIGN KEY (organization_id) REFERENCES organizations(id);

ALTER TABLE public."security_assets" ADD CONSTRAINT "security_assets_organization_id_integration_id_fkey" FOREIGN KEY (organization_id, integration_id) REFERENCES cloud_integrations(organization_id, id);

ALTER TABLE public."security_events" ADD CONSTRAINT "security_events_actor_user_id_fkey" FOREIGN KEY (actor_user_id) REFERENCES auth.users(id);

ALTER TABLE public."security_events" ADD CONSTRAINT "security_events_organization_id_asset_id_fkey" FOREIGN KEY (organization_id, asset_id) REFERENCES security_assets(organization_id, id);

ALTER TABLE public."security_events" ADD CONSTRAINT "security_events_organization_id_fkey" FOREIGN KEY (organization_id) REFERENCES organizations(id);

ALTER TABLE public."security_findings" ADD CONSTRAINT "security_findings_organization_id_asset_id_fkey" FOREIGN KEY (organization_id, asset_id) REFERENCES security_assets(organization_id, id);

ALTER TABLE public."security_findings" ADD CONSTRAINT "security_findings_organization_id_fkey" FOREIGN KEY (organization_id) REFERENCES organizations(id);

ALTER TABLE public."security_findings" ADD CONSTRAINT "security_findings_organization_id_source_event_id_fkey" FOREIGN KEY (organization_id, source_event_id) REFERENCES security_events(organization_id, id);

ALTER TABLE public."security_incidents" ADD CONSTRAINT "security_incidents_assigned_to_fkey" FOREIGN KEY (assigned_to) REFERENCES auth.users(id);

ALTER TABLE public."security_incidents" ADD CONSTRAINT "security_incidents_organization_id_fkey" FOREIGN KEY (organization_id) REFERENCES organizations(id);

ALTER TABLE public."security_risk_scores" ADD CONSTRAINT "security_risk_scores_organization_id_fkey" FOREIGN KEY (organization_id) REFERENCES organizations(id);

ALTER TABLE public."vader_detection_rules" ADD CONSTRAINT "vader_detection_rules_organization_id_fkey" FOREIGN KEY (organization_id) REFERENCES organizations(id);

ALTER TABLE public."vader_graph_edges" ADD CONSTRAINT "vader_graph_edges_organization_id_fkey" FOREIGN KEY (organization_id) REFERENCES organizations(id);

ALTER TABLE public."vader_graph_edges" ADD CONSTRAINT "vader_graph_edges_organization_id_source_node_id_fkey" FOREIGN KEY (organization_id, source_node_id) REFERENCES vader_graph_nodes(organization_id, id);

ALTER TABLE public."vader_graph_edges" ADD CONSTRAINT "vader_graph_edges_organization_id_target_node_id_fkey" FOREIGN KEY (organization_id, target_node_id) REFERENCES vader_graph_nodes(organization_id, id);

ALTER TABLE public."vader_graph_nodes" ADD CONSTRAINT "vader_graph_nodes_organization_id_fkey" FOREIGN KEY (organization_id) REFERENCES organizations(id);

ALTER TABLE public."vader_response_actions" ADD CONSTRAINT "vader_response_actions_approved_by_fkey" FOREIGN KEY (approved_by) REFERENCES auth.users(id);

ALTER TABLE public."vader_response_actions" ADD CONSTRAINT "vader_response_actions_organization_id_fkey" FOREIGN KEY (organization_id) REFERENCES organizations(id);

ALTER TABLE public."vader_response_actions" ADD CONSTRAINT "vader_response_actions_organization_id_incident_id_fkey" FOREIGN KEY (organization_id, incident_id) REFERENCES security_incidents(organization_id, id);

ALTER TABLE public."vader_response_actions" ADD CONSTRAINT "vader_response_actions_proposed_by_fkey" FOREIGN KEY (proposed_by) REFERENCES auth.users(id);

ALTER TABLE public."vader_simulations" ADD CONSTRAINT "vader_simulations_created_by_fkey" FOREIGN KEY (created_by) REFERENCES auth.users(id);

ALTER TABLE public."vader_simulations" ADD CONSTRAINT "vader_simulations_organization_id_fkey" FOREIGN KEY (organization_id) REFERENCES organizations(id);

ALTER TABLE public."vader_trust_scores" ADD CONSTRAINT "vader_trust_scores_organization_id_fkey" FOREIGN KEY (organization_id) REFERENCES organizations(id);

ALTER TABLE public."vader_trust_scores" ADD CONSTRAINT "vader_trust_scores_organization_id_user_id_fkey" FOREIGN KEY (organization_id, user_id) REFERENCES organization_members(organization_id, user_id);

CREATE INDEX audit_logs_org_created_idx ON public.audit_logs USING btree (organization_id, created_at DESC);

CREATE INDEX organization_invitations_org_idx ON public.organization_invitations USING btree (organization_id);

CREATE INDEX organization_members_user_idx ON public.organization_members USING btree (user_id);

CREATE UNIQUE INDEX organizations_domain_unique ON public.organizations USING btree (lower(domain)) WHERE (domain IS NOT NULL);

CREATE INDEX security_assets_org_type_idx ON public.security_assets USING btree (organization_id, asset_type);

CREATE INDEX security_events_actor_time_idx ON public.security_events USING btree (organization_id, actor_user_id, event_time DESC);

CREATE UNIQUE INDEX security_events_external_dedupe_idx ON public.security_events USING btree (organization_id, source, external_event_id) WHERE (external_event_id IS NOT NULL);

CREATE INDEX security_events_org_time_idx ON public.security_events USING btree (organization_id, event_time DESC);

CREATE INDEX security_findings_org_status_idx ON public.security_findings USING btree (organization_id, status, severity);

CREATE INDEX security_incidents_org_status_idx ON public.security_incidents USING btree (organization_id, status, detected_at DESC);

CREATE INDEX security_risk_scores_subject_idx ON public.security_risk_scores USING btree (organization_id, subject_type, subject_id, calculated_at DESC);

CREATE INDEX vader_rules_org_idx ON public.vader_detection_rules USING btree (organization_id, enabled);

CREATE INDEX vader_graph_edges_org_idx ON public.vader_graph_edges USING btree (organization_id, source_node_id);

CREATE INDEX vader_graph_nodes_org_idx ON public.vader_graph_nodes USING btree (organization_id, node_type);

CREATE INDEX vader_actions_org_idx ON public.vader_response_actions USING btree (organization_id, status);

CREATE INDEX vader_simulations_org_idx ON public.vader_simulations USING btree (organization_id, status);

CREATE INDEX vader_trust_org_user_idx ON public.vader_trust_scores USING btree (organization_id, user_id, calculated_at DESC);

CREATE FUNCTION public.handle_new_mesh_user()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
begin
  insert into public.profiles(id, full_name)
  values (
    new.id,
    new.raw_user_meta_data ->> 'full_name'
  )
  on conflict (id) do nothing;

  return new;
end;
$function$;

REVOKE ALL ON FUNCTION public.handle_new_mesh_user() FROM PUBLIC,anon,authenticated,service_role;

GRANT EXECUTE ON FUNCTION public.handle_new_mesh_user() TO PUBLIC;

GRANT EXECUTE ON FUNCTION public.handle_new_mesh_user() TO "postgres";

CREATE FUNCTION public.is_mesh_member(p_organization_id uuid, p_roles mesh_role[] DEFAULT NULL::mesh_role[])
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select exists (
    select 1
    from public.organization_members m
    where m.organization_id = p_organization_id
      and m.user_id = (select auth.uid())
      and m.status = 'active'
      and (
        p_roles is null
        or m.role = any(p_roles)
      )
  );
$function$;

REVOKE ALL ON FUNCTION public.is_mesh_member(uuid,public.mesh_role[]) FROM PUBLIC,anon,authenticated,service_role;

GRANT EXECUTE ON FUNCTION public.is_mesh_member(uuid,public.mesh_role[]) TO "postgres";

GRANT EXECUTE ON FUNCTION public.is_mesh_member(uuid,public.mesh_role[]) TO "authenticated";

ALTER TABLE public."audit_logs" ENABLE ROW LEVEL SECURITY;

ALTER TABLE public."cloud_integrations" ENABLE ROW LEVEL SECURITY;

ALTER TABLE public."incident_events" ENABLE ROW LEVEL SECURITY;

ALTER TABLE public."organization_invitations" ENABLE ROW LEVEL SECURITY;

ALTER TABLE public."organization_members" ENABLE ROW LEVEL SECURITY;

ALTER TABLE public."organizations" ENABLE ROW LEVEL SECURITY;

ALTER TABLE public."profiles" ENABLE ROW LEVEL SECURITY;

ALTER TABLE public."security_assets" ENABLE ROW LEVEL SECURITY;

ALTER TABLE public."security_events" ENABLE ROW LEVEL SECURITY;

ALTER TABLE public."security_findings" ENABLE ROW LEVEL SECURITY;

ALTER TABLE public."security_incidents" ENABLE ROW LEVEL SECURITY;

ALTER TABLE public."security_risk_scores" ENABLE ROW LEVEL SECURITY;

ALTER TABLE public."vader_detection_rules" ENABLE ROW LEVEL SECURITY;

ALTER TABLE public."vader_graph_edges" ENABLE ROW LEVEL SECURITY;

ALTER TABLE public."vader_graph_nodes" ENABLE ROW LEVEL SECURITY;

ALTER TABLE public."vader_response_actions" ENABLE ROW LEVEL SECURITY;

ALTER TABLE public."vader_simulations" ENABLE ROW LEVEL SECURITY;

ALTER TABLE public."vader_trust_scores" ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Owner and security can view audit logs" ON public."audit_logs" AS PERMISSIVE FOR SELECT TO "authenticated" USING (is_mesh_member(organization_id, ARRAY['owner'::mesh_role, 'security_team'::mesh_role]));

CREATE POLICY "Security reads cloud integrations" ON public."cloud_integrations" AS PERMISSIVE FOR SELECT TO "authenticated" USING (is_mesh_member(organization_id, ARRAY['security_team'::mesh_role]));

CREATE POLICY "Security reads incident evidence" ON public."incident_events" AS PERMISSIVE FOR SELECT TO "authenticated" USING (is_mesh_member(organization_id, ARRAY['security_team'::mesh_role]));

CREATE POLICY "Owner and HR can view invitations" ON public."organization_invitations" AS PERMISSIVE FOR SELECT TO "authenticated" USING (is_mesh_member(organization_id, ARRAY['owner'::mesh_role, 'hr'::mesh_role]));

CREATE POLICY "Members can view organization memberships" ON public."organization_members" AS PERMISSIVE FOR SELECT TO "authenticated" USING (is_mesh_member(organization_id));

CREATE POLICY "Members can view their organization" ON public."organizations" AS PERMISSIVE FOR SELECT TO "authenticated" USING (is_mesh_member(id));

CREATE POLICY "Users can view authorized profiles" ON public."profiles" AS PERMISSIVE FOR SELECT TO "authenticated" USING (((id = ( SELECT auth.uid() AS uid)) OR (EXISTS ( SELECT 1
   FROM organization_members m
  WHERE ((m.user_id = profiles.id) AND (m.status = 'active'::mesh_member_status) AND is_mesh_member(m.organization_id))))));

CREATE POLICY "Security reads assets" ON public."security_assets" AS PERMISSIVE FOR SELECT TO "authenticated" USING (is_mesh_member(organization_id, ARRAY['security_team'::mesh_role]));

CREATE POLICY "Security reads events" ON public."security_events" AS PERMISSIVE FOR SELECT TO "authenticated" USING (is_mesh_member(organization_id, ARRAY['security_team'::mesh_role]));

CREATE POLICY "Security reads findings" ON public."security_findings" AS PERMISSIVE FOR SELECT TO "authenticated" USING (is_mesh_member(organization_id, ARRAY['security_team'::mesh_role]));

CREATE POLICY "Security reads incidents" ON public."security_incidents" AS PERMISSIVE FOR SELECT TO "authenticated" USING (is_mesh_member(organization_id, ARRAY['security_team'::mesh_role]));

CREATE POLICY "Security reads risk scores" ON public."security_risk_scores" AS PERMISSIVE FOR SELECT TO "authenticated" USING (is_mesh_member(organization_id, ARRAY['security_team'::mesh_role]));

CREATE POLICY "Security reads detection rules" ON public."vader_detection_rules" AS PERMISSIVE FOR SELECT TO "authenticated" USING (is_mesh_member(organization_id, ARRAY['security_team'::mesh_role]));

CREATE POLICY "Security reads graph edges" ON public."vader_graph_edges" AS PERMISSIVE FOR SELECT TO "authenticated" USING (is_mesh_member(organization_id, ARRAY['security_team'::mesh_role]));

CREATE POLICY "Security reads graph nodes" ON public."vader_graph_nodes" AS PERMISSIVE FOR SELECT TO "authenticated" USING (is_mesh_member(organization_id, ARRAY['security_team'::mesh_role]));

CREATE POLICY "Security reads response actions" ON public."vader_response_actions" AS PERMISSIVE FOR SELECT TO "authenticated" USING (is_mesh_member(organization_id, ARRAY['security_team'::mesh_role]));

CREATE POLICY "Security reads simulations" ON public."vader_simulations" AS PERMISSIVE FOR SELECT TO "authenticated" USING (is_mesh_member(organization_id, ARRAY['security_team'::mesh_role]));

CREATE POLICY "Authorized trust score visibility" ON public."vader_trust_scores" AS PERMISSIVE FOR SELECT TO "authenticated" USING ((((user_id = ( SELECT auth.uid() AS uid)) AND is_mesh_member(organization_id)) OR is_mesh_member(organization_id, ARRAY['hr'::mesh_role, 'security_team'::mesh_role])));

REVOKE ALL ON TABLE public."audit_logs" FROM PUBLIC,anon,authenticated,service_role;

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."audit_logs" TO "anon";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."audit_logs" TO "authenticated";

GRANT DELETE,INSERT,MAINTAIN,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE ON TABLE public."audit_logs" TO "postgres";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."audit_logs" TO "service_role";

REVOKE ALL ON TABLE public."cloud_integrations" FROM PUBLIC,anon,authenticated,service_role;

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."cloud_integrations" TO "anon";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."cloud_integrations" TO "authenticated";

GRANT DELETE,INSERT,MAINTAIN,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE ON TABLE public."cloud_integrations" TO "postgres";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."cloud_integrations" TO "service_role";

REVOKE ALL ON TABLE public."incident_events" FROM PUBLIC,anon,authenticated,service_role;

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."incident_events" TO "anon";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."incident_events" TO "authenticated";

GRANT DELETE,INSERT,MAINTAIN,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE ON TABLE public."incident_events" TO "postgres";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."incident_events" TO "service_role";

REVOKE ALL ON TABLE public."organization_invitations" FROM PUBLIC,anon,authenticated,service_role;

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."organization_invitations" TO "anon";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."organization_invitations" TO "authenticated";

GRANT DELETE,INSERT,MAINTAIN,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE ON TABLE public."organization_invitations" TO "postgres";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."organization_invitations" TO "service_role";

REVOKE ALL ON TABLE public."organization_members" FROM PUBLIC,anon,authenticated,service_role;

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."organization_members" TO "anon";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."organization_members" TO "authenticated";

GRANT DELETE,INSERT,MAINTAIN,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE ON TABLE public."organization_members" TO "postgres";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."organization_members" TO "service_role";

REVOKE ALL ON TABLE public."organizations" FROM PUBLIC,anon,authenticated,service_role;

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."organizations" TO "anon";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."organizations" TO "authenticated";

GRANT DELETE,INSERT,MAINTAIN,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE ON TABLE public."organizations" TO "postgres";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."organizations" TO "service_role";

REVOKE ALL ON TABLE public."profiles" FROM PUBLIC,anon,authenticated,service_role;

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."profiles" TO "anon";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."profiles" TO "authenticated";

GRANT DELETE,INSERT,MAINTAIN,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE ON TABLE public."profiles" TO "postgres";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."profiles" TO "service_role";

REVOKE ALL ON TABLE public."security_assets" FROM PUBLIC,anon,authenticated,service_role;

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."security_assets" TO "anon";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."security_assets" TO "authenticated";

GRANT DELETE,INSERT,MAINTAIN,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE ON TABLE public."security_assets" TO "postgres";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."security_assets" TO "service_role";

REVOKE ALL ON TABLE public."security_events" FROM PUBLIC,anon,authenticated,service_role;

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."security_events" TO "anon";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."security_events" TO "authenticated";

GRANT DELETE,INSERT,MAINTAIN,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE ON TABLE public."security_events" TO "postgres";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."security_events" TO "service_role";

REVOKE ALL ON TABLE public."security_findings" FROM PUBLIC,anon,authenticated,service_role;

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."security_findings" TO "anon";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."security_findings" TO "authenticated";

GRANT DELETE,INSERT,MAINTAIN,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE ON TABLE public."security_findings" TO "postgres";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."security_findings" TO "service_role";

REVOKE ALL ON TABLE public."security_incidents" FROM PUBLIC,anon,authenticated,service_role;

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."security_incidents" TO "anon";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."security_incidents" TO "authenticated";

GRANT DELETE,INSERT,MAINTAIN,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE ON TABLE public."security_incidents" TO "postgres";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."security_incidents" TO "service_role";

REVOKE ALL ON TABLE public."security_risk_scores" FROM PUBLIC,anon,authenticated,service_role;

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."security_risk_scores" TO "anon";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."security_risk_scores" TO "authenticated";

GRANT DELETE,INSERT,MAINTAIN,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE ON TABLE public."security_risk_scores" TO "postgres";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."security_risk_scores" TO "service_role";

REVOKE ALL ON TABLE public."vader_detection_rules" FROM PUBLIC,anon,authenticated,service_role;

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."vader_detection_rules" TO "anon";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."vader_detection_rules" TO "authenticated";

GRANT DELETE,INSERT,MAINTAIN,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE ON TABLE public."vader_detection_rules" TO "postgres";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."vader_detection_rules" TO "service_role";

REVOKE ALL ON TABLE public."vader_graph_edges" FROM PUBLIC,anon,authenticated,service_role;

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."vader_graph_edges" TO "anon";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."vader_graph_edges" TO "authenticated";

GRANT DELETE,INSERT,MAINTAIN,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE ON TABLE public."vader_graph_edges" TO "postgres";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."vader_graph_edges" TO "service_role";

REVOKE ALL ON TABLE public."vader_graph_nodes" FROM PUBLIC,anon,authenticated,service_role;

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."vader_graph_nodes" TO "anon";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."vader_graph_nodes" TO "authenticated";

GRANT DELETE,INSERT,MAINTAIN,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE ON TABLE public."vader_graph_nodes" TO "postgres";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."vader_graph_nodes" TO "service_role";

REVOKE ALL ON TABLE public."vader_response_actions" FROM PUBLIC,anon,authenticated,service_role;

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."vader_response_actions" TO "anon";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."vader_response_actions" TO "authenticated";

GRANT DELETE,INSERT,MAINTAIN,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE ON TABLE public."vader_response_actions" TO "postgres";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."vader_response_actions" TO "service_role";

REVOKE ALL ON TABLE public."vader_simulations" FROM PUBLIC,anon,authenticated,service_role;

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."vader_simulations" TO "anon";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."vader_simulations" TO "authenticated";

GRANT DELETE,INSERT,MAINTAIN,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE ON TABLE public."vader_simulations" TO "postgres";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."vader_simulations" TO "service_role";

REVOKE ALL ON TABLE public."vader_trust_scores" FROM PUBLIC,anon,authenticated,service_role;

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."vader_trust_scores" TO "anon";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."vader_trust_scores" TO "authenticated";

GRANT DELETE,INSERT,MAINTAIN,REFERENCES,SELECT,TRIGGER,TRUNCATE,UPDATE ON TABLE public."vader_trust_scores" TO "postgres";

GRANT MAINTAIN,REFERENCES,TRIGGER,TRUNCATE ON TABLE public."vader_trust_scores" TO "service_role";

REVOKE ALL ON SEQUENCE public.security_incidents_incident_number_seq FROM PUBLIC,anon,authenticated,service_role;

GRANT SELECT ON SEQUENCE public.security_incidents_incident_number_seq TO "postgres";

GRANT UPDATE ON SEQUENCE public.security_incidents_incident_number_seq TO "postgres";

GRANT USAGE ON SEQUENCE public.security_incidents_incident_number_seq TO "postgres";

DO $postflight$
DECLARE table_oids oid[];
BEGIN
 SELECT array_agg(c.oid) INTO table_oids FROM pg_catalog.pg_class c
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname IN ('audit_logs','cloud_integrations','incident_events','organization_invitations','organization_members','organizations','profiles','security_assets','security_events','security_findings','security_incidents','security_risk_scores','vader_detection_rules','vader_graph_edges','vader_graph_nodes','vader_response_actions','vader_simulations','vader_trust_scores');
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
 IF (SELECT jsonb_build_object(
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
)) IS DISTINCT FROM current_setting('mesh_test.native_snapshot')::jsonb THEN
  RAISE EXCEPTION 'Native roles/ACLs/functions/events/Auth application triggers changed; transaction aborted';
 END IF;
END
$postflight$;

-- No application data or synthetic Auth users are loaded by this schema file.

COMMIT;
