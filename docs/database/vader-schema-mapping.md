# VADER Phase 2: verified schema mapping and recommendations

Analysis only; no database changes or Phase 2 implementation. This document supersedes the missing-evidence assumptions in `vader-phase2-integration-plan.md`; its proposed file layout remains useful.

Source: `supabase/inspection/mesh_inspection.json` (540148 bytes), SHA-256 `0bb6b94031f1d0fe1fd843a20697ed49b4785b9c5e9696014e932c2b532d1fa4`.
Captured `2026-10-29T15:02:23.31302+00:00`, PostgreSQL `17.11`, database `postgres`, inspection role `postgres`.
The export does not contain a project reference. Association with `khweikfvsnervfuswhon` relies on the user-provided export provenance, not an embedded project identifier. No current remote connection was made.

## Export validation

All 12 required section keys parse with the expected object/array payload shapes. The inventory has exactly 18 unique reported application tables; no missing or unexpected tables. All five target tables have contiguous column positions, unique column names, validated nondeferrable constraints and valid/ready indexes. No identity fields should be inferred from defaults alone.

| Section | Payload size |
| --- | --- |
| 01_inventory | 10 object keys |
| 02_columns | 165 records |
| 03_constraints | 85 records |
| 04_indexes | 46 records |
| 05_enums | 2 records |
| 06_functions | 9 records |
| 07_function_definitions | 3 records |
| 08_triggers | 125 records |
| 09_rls_status | 18 records |
| 10_policies | 18 records |
| 11_grants | 442 records |
| 12_extensions_dependencies | 2 object keys |

Section 12 contains 341 dependency records. Three public function definitions in section 07 are explicitly WITHHELD; this is an evidence limitation, not a parse failure. Metadata is verified against this capture, not exercised as live permissions. Role memberships, role attributes, sequence definitions/ACLs outside public, event-trigger registration, default function arguments and full routine settings are not comprehensively captured.

## Exact database definitions for the five persistence tables

`?` means no column default. All timestamps below are `timestamp with time zone`. Nullable columns without defaults may be omitted. Identity generation is separately stated. Constraint/index SQL below is quoted evidence only, not a migration.

### public.security_events

| Column | PostgreSQL type | Nullable | Default / identity |
| --- | --- | --- | --- |
| `id` | `uuid` | no | `gen_random_uuid()` |
| `organization_id` | `uuid` | no | `?` |
| `asset_id` | `uuid` | yes | `?` |
| `source` | `text` | no | `?` |
| `external_event_id` | `text` | yes | `?` |
| `event_type` | `text` | no | `?` |
| `actor_user_id` | `uuid` | yes | `?` |
| `actor_identifier` | `text` | yes | `?` |
| `action` | `text` | yes | `?` |
| `outcome` | `text` | yes | `?` |
| `source_ip` | `inet` | yes | `?` |
| `severity` | `text` | no | `'info'::text` |
| `event_time` | `timestamp with time zone` | no | `?` |
| `received_at` | `timestamp with time zone` | no | `now()` |
| `details` | `jsonb` | no | `'{}'::jsonb` |

Constraints (all validated; immediate and nondeferrable):

- `security_events_actor_user_id_fkey`: `FOREIGN KEY (actor_user_id) REFERENCES auth.users(id)`.
- `security_events_organization_id_asset_id_fkey`: `FOREIGN KEY (organization_id, asset_id) REFERENCES security_assets(organization_id, id)`.
- `security_events_organization_id_fkey`: `FOREIGN KEY (organization_id) REFERENCES organizations(id)`.
- `security_events_organization_id_id_key`: `UNIQUE (organization_id, id)`.
- `security_events_pkey`: `PRIMARY KEY (id)`.
- `security_events_severity_check`: `CHECK ((severity = ANY (ARRAY['info'::text, 'low'::text, 'medium'::text, 'high'::text, 'critical'::text])))`.

Indexes (all valid and ready):

- `security_events_actor_time_idx`: `CREATE INDEX security_events_actor_time_idx ON public.security_events USING btree (organization_id, actor_user_id, event_time DESC)`.
- `security_events_external_dedupe_idx`: `CREATE UNIQUE INDEX security_events_external_dedupe_idx ON public.security_events USING btree (organization_id, source, external_event_id) WHERE (external_event_id IS NOT NULL)`.
- `security_events_org_time_idx`: `CREATE INDEX security_events_org_time_idx ON public.security_events USING btree (organization_id, event_time DESC)`.
- `security_events_organization_id_id_key`: `CREATE UNIQUE INDEX security_events_organization_id_id_key ON public.security_events USING btree (organization_id, id)`.
- `security_events_pkey`: `CREATE UNIQUE INDEX security_events_pkey ON public.security_events USING btree (id)`.

### public.security_findings

| Column | PostgreSQL type | Nullable | Default / identity |
| --- | --- | --- | --- |
| `id` | `uuid` | no | `gen_random_uuid()` |
| `organization_id` | `uuid` | no | `?` |
| `asset_id` | `uuid` | yes | `?` |
| `source_event_id` | `uuid` | yes | `?` |
| `title` | `text` | no | `?` |
| `description` | `text` | yes | `?` |
| `finding_type` | `text` | no | `?` |
| `severity` | `text` | no | `'medium'::text` |
| `status` | `text` | no | `'open'::text` |
| `evidence` | `jsonb` | no | `'{}'::jsonb` |
| `remediation` | `text` | yes | `?` |
| `detected_at` | `timestamp with time zone` | no | `now()` |
| `resolved_at` | `timestamp with time zone` | yes | `?` |

Constraints (all validated; immediate and nondeferrable):

- `security_findings_organization_id_asset_id_fkey`: `FOREIGN KEY (organization_id, asset_id) REFERENCES security_assets(organization_id, id)`.
- `security_findings_organization_id_fkey`: `FOREIGN KEY (organization_id) REFERENCES organizations(id)`.
- `security_findings_organization_id_id_key`: `UNIQUE (organization_id, id)`.
- `security_findings_organization_id_source_event_id_fkey`: `FOREIGN KEY (organization_id, source_event_id) REFERENCES security_events(organization_id, id)`.
- `security_findings_pkey`: `PRIMARY KEY (id)`.
- `security_findings_severity_check`: `CHECK ((severity = ANY (ARRAY['info'::text, 'low'::text, 'medium'::text, 'high'::text, 'critical'::text])))`.
- `security_findings_status_check`: `CHECK ((status = ANY (ARRAY['open'::text, 'investigating'::text, 'remediating'::text, 'resolved'::text, 'false_positive'::text, 'accepted_risk'::text])))`.

Indexes (all valid and ready):

- `security_findings_org_status_idx`: `CREATE INDEX security_findings_org_status_idx ON public.security_findings USING btree (organization_id, status, severity)`.
- `security_findings_organization_id_id_key`: `CREATE UNIQUE INDEX security_findings_organization_id_id_key ON public.security_findings USING btree (organization_id, id)`.
- `security_findings_pkey`: `CREATE UNIQUE INDEX security_findings_pkey ON public.security_findings USING btree (id)`.

### public.security_incidents

| Column | PostgreSQL type | Nullable | Default / identity |
| --- | --- | --- | --- |
| `id` | `uuid` | no | `gen_random_uuid()` |
| `organization_id` | `uuid` | no | `?` |
| `incident_number` | `bigint` | no | `?; GENERATED ALWAYS AS IDENTITY` |
| `title` | `text` | no | `?` |
| `description` | `text` | yes | `?` |
| `severity` | `text` | no | `'medium'::text` |
| `status` | `text` | no | `'detected'::text` |
| `risk_score` | `numeric(5,2)` | yes | `?` |
| `confidence` | `numeric(4,3)` | yes | `?` |
| `assigned_to` | `uuid` | yes | `?` |
| `summary` | `jsonb` | no | `'{}'::jsonb` |
| `detected_at` | `timestamp with time zone` | no | `now()` |
| `resolved_at` | `timestamp with time zone` | yes | `?` |
| `created_at` | `timestamp with time zone` | no | `now()` |

Constraints (all validated; immediate and nondeferrable):

- `security_incidents_assigned_to_fkey`: `FOREIGN KEY (assigned_to) REFERENCES auth.users(id)`.
- `security_incidents_confidence_check`: `CHECK (((confidence >= (0)::numeric) AND (confidence <= (1)::numeric)))`.
- `security_incidents_incident_number_key`: `UNIQUE (incident_number)`.
- `security_incidents_organization_id_fkey`: `FOREIGN KEY (organization_id) REFERENCES organizations(id)`.
- `security_incidents_organization_id_id_key`: `UNIQUE (organization_id, id)`.
- `security_incidents_pkey`: `PRIMARY KEY (id)`.
- `security_incidents_risk_score_check`: `CHECK (((risk_score >= (0)::numeric) AND (risk_score <= (100)::numeric)))`.
- `security_incidents_severity_check`: `CHECK ((severity = ANY (ARRAY['low'::text, 'medium'::text, 'high'::text, 'critical'::text])))`.
- `security_incidents_status_check`: `CHECK ((status = ANY (ARRAY['detected'::text, 'triaged'::text, 'investigating'::text, 'contained'::text, 'remediating'::text, 'recovering'::text, 'resolved'::text, 'false_positive'::text])))`.

Indexes (all valid and ready):

- `security_incidents_incident_number_key`: `CREATE UNIQUE INDEX security_incidents_incident_number_key ON public.security_incidents USING btree (incident_number)`.
- `security_incidents_org_status_idx`: `CREATE INDEX security_incidents_org_status_idx ON public.security_incidents USING btree (organization_id, status, detected_at DESC)`.
- `security_incidents_organization_id_id_key`: `CREATE UNIQUE INDEX security_incidents_organization_id_id_key ON public.security_incidents USING btree (organization_id, id)`.
- `security_incidents_pkey`: `CREATE UNIQUE INDEX security_incidents_pkey ON public.security_incidents USING btree (id)`.

### public.incident_events

| Column | PostgreSQL type | Nullable | Default / identity |
| --- | --- | --- | --- |
| `organization_id` | `uuid` | no | `?` |
| `incident_id` | `uuid` | no | `?` |
| `event_id` | `uuid` | no | `?` |
| `relationship` | `text` | no | `'related'::text` |
| `created_at` | `timestamp with time zone` | no | `now()` |

Constraints (all validated; immediate and nondeferrable):

- `incident_events_organization_id_event_id_fkey`: `FOREIGN KEY (organization_id, event_id) REFERENCES security_events(organization_id, id)`.
- `incident_events_organization_id_fkey`: `FOREIGN KEY (organization_id) REFERENCES organizations(id)`.
- `incident_events_organization_id_incident_id_fkey`: `FOREIGN KEY (organization_id, incident_id) REFERENCES security_incidents(organization_id, id) ON DELETE CASCADE`.
- `incident_events_pkey`: `PRIMARY KEY (incident_id, event_id)`.

Indexes (all valid and ready):

- `incident_events_pkey`: `CREATE UNIQUE INDEX incident_events_pkey ON public.incident_events USING btree (incident_id, event_id)`.

### public.security_risk_scores

| Column | PostgreSQL type | Nullable | Default / identity |
| --- | --- | --- | --- |
| `id` | `uuid` | no | `gen_random_uuid()` |
| `organization_id` | `uuid` | no | `?` |
| `subject_type` | `text` | no | `?` |
| `subject_id` | `uuid` | no | `?` |
| `score` | `numeric(5,2)` | no | `?` |
| `confidence` | `numeric(4,3)` | yes | `?` |
| `factors` | `jsonb` | no | `'{}'::jsonb` |
| `explanation` | `text` | yes | `?` |
| `model_version` | `text` | no | `?` |
| `calculated_at` | `timestamp with time zone` | no | `now()` |

Constraints (all validated; immediate and nondeferrable):

- `security_risk_scores_confidence_check`: `CHECK (((confidence >= (0)::numeric) AND (confidence <= (1)::numeric)))`.
- `security_risk_scores_organization_id_fkey`: `FOREIGN KEY (organization_id) REFERENCES organizations(id)`.
- `security_risk_scores_pkey`: `PRIMARY KEY (id)`.
- `security_risk_scores_score_check`: `CHECK (((score >= (0)::numeric) AND (score <= (100)::numeric)))`.
- `security_risk_scores_subject_type_check`: `CHECK ((subject_type = ANY (ARRAY['identity'::text, 'asset'::text, 'finding'::text, 'incident'::text])))`.

Indexes (all valid and ready):

- `security_risk_scores_pkey`: `CREATE UNIQUE INDEX security_risk_scores_pkey ON public.security_risk_scores USING btree (id)`.
- `security_risk_scores_subject_idx`: `CREATE INDEX security_risk_scores_subject_idx ON public.security_risk_scores USING btree (organization_id, subject_type, subject_id, calculated_at DESC)`.

## Exact grant evidence

All five target tables have the same direct relation privilege sets; there are no exported column grants:

| Role | Direct relation privileges |
| --- | --- |
| anon | MAINTAIN, REFERENCES, TRIGGER, TRUNCATE |
| authenticated | MAINTAIN, REFERENCES, TRIGGER, TRUNCATE |
| service_role | MAINTAIN, REFERENCES, TRIGGER, TRUNCATE |
| postgres | DELETE, INSERT, MAINTAIN, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE |

The public schema grants USAGE to PUBLIC, anon, authenticated, postgres and service_role; CREATE belongs to pg_database_owner. Default ACLs for postgres-created relations repeat the anomalous non-DML grants to anon/authenticated/service_role. Supabase_admin defaults separately grant broad DML to these roles on future objects created by that role. Default ACLs do not repair existing tables; creator identity matters. Exported direct ACLs are not a complete inherited effective-privilege audit.


## Python-to-database mapping

These are proposed adapter contracts using verified existing columns. Synthesized
values are identified explicitly; they are not Phase 1 fields. Do not bulk-insert
model dumps. Source identities and tenant scope must come from trusted ingestion
context. Never trust a body-supplied organization without authorization.

### SecurityEvent -> security_events

| Python/context | Actual column | Adapter behavior |
| --- | --- | --- |
| organization_id | organization_id | UUID from authorized ingestion scope; must match event |
| event_type | event_type | Preserve four Phase 1 literals; DB text has no event-type CHECK |
| actor_identifier | actor_identifier | Preserve normalized nonblank string; DB permits NULL but VADER must not |
| event_time | event_time | Explicit UTC ISO timestamp; no DB default |
| source_ip | source_ip | Serialize validated IPv4/IPv6 as inet-compatible string or NULL |
| details | details | JSON object, retain strict validated measurements; bound size and sanitize secrets |
| trusted adapter source | source | Required new envelope value; no default. Namespace source by integration to prevent same-tenant upstream-ID collisions |
| stable upstream event identity | external_event_id | Require non-NULL stable ID for Phase 2, including synthetic events; DB itself permits NULL |
| persisted ID | id | Retain inserted UUID or deterministic ID described below; never regenerate on retries |
| no Phase 1 value | severity | Omit, retaining info; detector severity belongs in findings |
| no Phase 1 value | asset_id, actor_user_id, action, outcome | Omit/NULL initially; enrich only with verified associations |
| database receipt time | received_at | Omit, use now(); do not replace occurrence time with receipt time |

There is no integration_id column. Do not invent one. actor_user_id references
Auth users and must not be populated from actor_identifier or caller identity.

### Finding -> security_findings

| Python/context | Actual column | Adapter behavior |
| --- | --- | --- |
| organization_id | organization_id | Assert same tenant as source event |
| persisted event ID | source_event_id | Always populate for VADER even though nullable; composite tenant FK already exists |
| rule_code | finding_type | Store exact stable code; no rule registry FK required |
| rule-code title catalog | title | Required synthesized human-readable title, e.g. Excessive login failures |
| explanation | description | Preserve rule explanation |
| severity | severity | high/critical already satisfy DB severity CHECK |
| evidence + actor_identifier | evidence | Preserve finding evidence keys and add actor_identifier and detector_version; no standalone actor column |
| no Phase 1 value | status | Omit, use open; retries must not reset triage state |
| optional validated source asset | asset_id | NULL initially; composite tenant FK available |
| ingestion/detection clock | detected_at | Initial DB now() is appropriate; event time remains in evidence |
| deterministic identity | id | See idempotency contract |
| no Phase 1 value | remediation, resolved_at | Omit/NULL; never fabricate remediation or resolution |

Preserve measured fields (failed_attempts, authorized, bytes_transferred),
event_time and source_ip in evidence. rule_code is represented by finding_type,
not by a nonexistent rule_code column.

### Correlation result -> security_incidents

| Python/context | Actual column | Adapter behavior |
| --- | --- | --- |
| organization_id | organization_id | Authorized tenant, matching every linked event |
| synthesized chain title | title | Required text, e.g. Ordered four-stage suspicious activity |
| explanation | description | Preserve qualified candidate-chain explanation |
| chain_id, actor_identifier, start_time, end_time, evidence, detection_rules | summary | Preserve these named values plus ordered persisted event IDs and correlation_version |
| matched_events | incident_events + summary | Resolve to persisted IDs and link each; avoid unnecessary duplication of full raw events in summary |
| max matched finding severity | severity | Proposed initial severity critical for this complete chain; do not confuse it with risk_level |
| scoped score_risk output risk_score | risk_score | Integer fits numeric(5,2), range 0..100 |
| scoped confidence_estimate | confidence | Fits numeric(4,3); explain evidence completeness in summary |
| deterministic sequence identity | id | UUID, not raw 64-character chain_id; preserve original hash in summary |
| no caller value | incident_number | GENERATED ALWAYS AS IDENTITY; OMIT on insert, not a missing/default bug |
| no caller value | status | Omit, use detected; replay must preserve investigation status |
| database clock | detected_at, created_at | Omit; summary retains occurrence-time range |
| no Phase 1 value | assigned_to, resolved_at | Omit/NULL; assignment needs same-tenant membership validation |

The identity-backed global unique incident_number already handles numbering; no
new numbering column, max(number)+1 algorithm, or numbering trigger is needed.

### Correlation matched events -> incident_events

| Python/context | Actual column | Adapter behavior |
| --- | --- | --- |
| organization_id | organization_id | Same as incident and event |
| persisted incident UUID | incident_id | Never use raw content hash as UUID |
| persisted event UUID | event_id | Resolve via normalized source identity and persisted lookup, not timestamp alone |
| chain stage | relationship | Optionally use documented stage labels; text has no CHECK. Otherwise retain related |
| database clock | created_at | Omit, use now() |

The PK (incident_id,event_id) already prevents duplicate links. Both parent
references use composite organization FKs. ON DELETE CASCADE applies only to the
incident parent link; event FK is NO ACTION. There is no stage position column;
retain explicit ordered IDs in incident summary rather than adding one now.

### RiskResult -> security_risk_scores

| Python/context | Actual column | Adapter behavior |
| --- | --- | --- |
| authorized tenant | organization_id | Explicit; RiskResult itself has no organization field |
| risk_score | score | Map name exactly, numeric(5,2) |
| confidence_estimate | confidence | numeric(4,3), already rounded to three places |
| explanation | explanation | Preserve formula narrative |
| contributing_factors | factors.contributing_factors | JSON object, retain all weights |
| risk_level | factors.risk_level | No standalone risk_level column |
| confidence_explanation | factors.confidence_explanation | Preserve distinction from compromise probability |
| immutable input revision | factors.input_revision | Proposed adapter metadata for reproducibility |
| scoring algorithm version | model_version | Required server constant, e.g. vader-risk-v1; no DB default |
| scoring target kind | subject_type | Initial scope finding or incident only |
| persisted finding/incident UUID | subject_id | UUID of same-tenant target; not actor string or event UUID |
| deterministic score identity | id | Include scope, input revision, algorithm version |
| database clock | calculated_at | Omit on first insertion, preserve on replay |

subject_type permits identity, asset, finding, incident. It does NOT permit event
or organization. An ordinary login can be ingested with no finding; its Phase 1
zero-risk response cannot be persisted as an event score in the current schema.
For the minimum Phase 2 scope, persist finding/incident scores only and retain
zero-event scoring as a transient API result. Adding event scope is optional
future scope expansion, not required to integrate existing supported subjects.

## RLS and authorization findings

All 18 tables have RLS enabled, none forced, owner postgres. Each of the five
target tables has exactly one permissive SELECT policy for authenticated:

| Table | Policy name |
| --- | --- |
| security_events | Security reads events |
| security_findings | Security reads findings |
| security_incidents | Security reads incidents |
| incident_events | Security reads incident evidence |
| security_risk_scores | Security reads risk scores |

Each USING is exactly
`is_mesh_member(organization_id, ARRAY['security_team'::mesh_role])`.
Each WITH CHECK is NULL. There are no INSERT/UPDATE/DELETE/ALL policies for these
tables. NULL WITH CHECK on a SELECT-only policy is not permission to insert.
The declared SELECT policies also lack a direct authenticated SELECT grant in
the exported ACLs. Owner/HR access is not established by these expressions; the
helper's withheld body could contain owner overrides, which must be reviewed.

`is_mesh_member(p_organization_id uuid, p_roles mesh_role[])` is SQL, STABLE,
SECURITY DEFINER, postgres-owned, not strict, and has routine settings. EXECUTE
is directly granted to postgres and authenticated, not PUBLIC. Its body,
search_path and argument defaults are absent. Cannot verify auth.uid matching,
active/suspended handling, role evaluation, NULL input behavior or recursion
safety. The exported enums are mesh_role (owner, hr, senior_developer,
junior_developer, security_team) and mesh_member_status (pending, active,
suspended, offboarded). VADER severity/status are TEXT CHECKs, not enums.

Other public routines: handle_new_mesh_user (PL/pgSQL SECURITY DEFINER trigger
function) and rls_auto_enable (PL/pgSQL SECURITY DEFINER event-trigger function),
both with PUBLIC EXECUTE and withheld definitions/settings. The only exported
noninternal row trigger is on_mesh_auth_user_created, AFTER INSERT on auth.users,
calling handle_new_mesh_user. No custom write/tenant validation row trigger is
recorded for the five target tables. Event-trigger registration is not inspected;
rls_auto_enable's mere presence does not prove automatic RLS activation.

Only public custom functions and referenced managed functions appear; no existing
analysis-bundle transaction routine is represented. The three withheld public
functions are not candidates to repurpose for VADER persistence.

### Permission and cross-tenant risks

1. **High priority: TRUNCATE granted to anon/authenticated/service_role.** RLS
   does not apply to TRUNCATE (or REFERENCES). A SQL-capable execution path under
   these roles could affect every tenant; FK relationships may require several
   tables together. This is not proof that an ordinary browser REST request can
   execute TRUNCATE. Remove these unnecessary powers, rather than relying on API
   surface restrictions. Review TRIGGER, REFERENCES and MAINTAIN as well.
2. **Reads/writes blocked under directly exported ACLs.** Neither authenticated
   nor service_role has direct SELECT/INSERT/UPDATE/DELETE on target tables.
   No column-level grants were exported. Inherited role memberships were not
   inspected, so effective rights require separate confirmation. RLS bypass does
   not supply absent SQL privileges. Do not assume a secret key fixes this.
3. **Composite FKs are already strong.** Findings->events/assets and links->
   incidents/events preserve organization consistency; do not add duplicate
   tenant columns or recreate these constraints.
4. **Polymorphic risk subjects have no FK/validation trigger.** A tenant A risk
   row can name a tenant B or nonexistent subject UUID if a writer can insert it.
   Row-level organization checks alone do not validate subject ownership.
5. **actor_user_id / assigned_to only reference auth.users(id).** They do not
   establish organization membership. Keep NULL initially; verify membership
   before future enrichment/assignment and consider database validation then.
6. **Privileged identities bypass RLS.** Owner postgres is exempt absent forced
   RLS; service_role normally bypasses RLS. Do not use either as the normal tenant
   authorization mechanism. Role attributes/membership need inspection to prove
   effective rights, and forced RLS does not stop BYPASSRLS identities.
7. **Actor namespace and untrusted evidence.** Same textual actor across sources
   can represent different principals. Define a trusted canonical identity before
   correlation; filter organization AND canonical actor. Do not infer attacker
   identity from the authenticated ingestion principal or accept secret-bearing
   freeform details without size/sanitization controls.

PostgreSQL semantics: [Row security](https://www.postgresql.org/docs/17/ddl-rowsecurity.html).
Supabase semantics: [RLS](https://supabase.com/docs/guides/database/postgres/row-level-security)
and [API security](https://supabase.com/docs/guides/api/securing-your-api).

## Existing capabilities and gaps

| Operation | Existing schema support | Remaining blocker |
| --- | --- | --- |
| Store normalized events | All Phase 1 fields fit; source additionally required | Backend write authorization and non-NULL stable upstream ID contract |
| Event deduplication | Unique (organization_id,source,external_event_id) WHERE ID IS NOT NULL | NULL IDs bypass dedupe; partial-index conflict inference needs matching predicate or transactional insert/conflict/select, not blind SDK upsert |
| Store findings | Fields fit title/description/finding_type/evidence | No semantic event/rule/version unique key; backend must supply title and idempotency |
| Store candidate chains | summary JSONB preserves complete explanation and range; identity numbering exists | Stable incident identity and atomic creation of links |
| Link incident evidence | Composite tenant FKs and pair PK already present | Transaction boundary with incident and score |
| Store risk explanations | score/confidence/factors/explanation/model_version fit | No event subject; no polymorphic integrity; no revision dedupe key except ID |
| Authenticated security-team reads | SELECT policy expression exists | Missing direct SELECT grant; helper implementation unreviewed |
| Authenticated ingestion writes | No write policies or direct write grants | Explicit server-only authorization design required |
| service_role persistence | USAGE exists, bypass normally applies | Missing direct DML; bypass would remove tenant RLS enforcement anyway |
| Efficient actor history | organization/time index exists | actor_time index uses actor_user_id, while engine uses actor_identifier; add matching index only after workload assessment |

Indexes for source_event/rule uniqueness, incident chain identity, and risk
revision identity do not exist. Incident_number uniqueness is numbering, not
chain deduplication. Source-event linkage in findings is nullable; enforce it in
VADER without globally changing other finding types. Checks validate score and
confidence ranges but not evidence shape, algorithm truth or cross-tenant inputs.

## Smallest safe Phase 2 change set (recommendations only)

### Required review before changes

Privately recover/review the is_mesh_member definition, including actual settings
and defaults. Verify effective role memberships/attributes and sequence ownership
for incident_number; neither is sufficiently proven by this export. Preserve
managed schemas and extensions (pg_stat_statements, pgcrypto, plpgsql,
supabase_vault, uuid-ossp). Do not export vault data or copy managed auth objects.
The 341 recorded cross-schema dependencies include managed trigger functions,
auth references and schema/extension links; they do not prove dynamic-SQL safety.

### Minimal database authorization changes

1. Revoke unnecessary TRUNCATE/TRIGGER/REFERENCES/MAINTAIN privileges for API roles
   on these tables, reviewing related application tables and creator-specific
   default grants so unsafe rights do not reappear. Do not replace them with ALL.
2. If security-team reads are required, add authenticated SELECT on the five
   tables, retaining existing RLS, after the helper body is verified. No frontend
   INSERT/UPDATE/DELETE grants or write policies are needed for the chosen design.
3. Provide one restricted transactional backend ingestion routine, callable only
   by a dedicated non-frontend machine role. Prefer a limited non-login owner
   with only the required table/sequence rights, not postgres. If definer security
   is used, fix search_path, revoke PUBLIC/anon/authenticated EXECUTE, derive/verify
   the integration's organization from trusted server-controlled authorization,
   validate every related UUID, and reject payload scope overrides. A single
   global credential plus arbitrary tenant input is not database tenant isolation.
   Tenant-scoped caller credentials or an independently enforced caller-to-tenant
   mapping must be agreed before implementation; the current schema exposes no
   verified machine identity mechanism. Do not invent an integration credential
   column. Alternative invoker/RLS design is valid but needs explicit machine-role
   grants and write policies; do not implement both paths speculatively.
4. Enforce same-tenant risk subject existence. The minimum restricted-writer scope
   is finding/incident and can validate/lock the referenced row inside that same
   transaction routine, with no public INSERT rights. This is not a global FK:
   deletes or other writers can still invalidate polymorphic references. Require
   an explicit retention/no-delete contract and control all write paths for this
   scope. If that contract cannot be guaranteed, add a database validation/deletion
   mechanism or typed tenant-scoped FKs before claiming durable subject integrity.

### Avoid unnecessary columns and indexes

The minimum schema path can use **existing UUID PKs for deterministic retry IDs**:
versioned UUIDv5 namespaces keyed by tenant + trusted source identity for events;
persisted event ID + finding_type + detector version for findings; tenant +
ordered persisted event IDs + correlation version for incidents; subject type/ID
+ immutable input revision + model_version for scores. Links already have a PK.
Use trusted deterministic IDs with collision/payload equality checks; never
accept arbitrary client IDs as proof of idempotency. On replay do not overwrite
triage fields or accept changed immutable payloads. UUID uniqueness is enforced,
but semantic identity depends on all writers following this reviewed contract.

This avoids mandatory new fingerprint/version columns: preserve full hashes and
version metadata in existing evidence/summary/factors JSONB and model_version.
The existing source partial unique index remains an independent event guard.
The raw SHA-256 chain_id is not a UUID; do not truncate/cast it into id.

If independently written rows must also obey semantic uniqueness, add explicit
unique keys/expression indexes for finding event/rule/version, incident chain
identity and score input revision after duplicate-data checks. These are optional
hardening for the single restricted deterministic writer, required for a general
multi-writer contract. The schema export contains no table rows, so existing
semantic duplicate counts cannot be assessed here. No guessed cleanup allowed.

Do not add event risk scope, new evidence columns, numbering infrastructure,
incident ordering columns or a queue table for the minimum version. Restrict risk
persistence to finding/incident. Process a bounded bundle synchronously in one
transaction; return success after commit. Retry whole bundles with identical IDs
on unknown outcomes. Concurrent/correlation processing for one tenant/actor needs
serialization (e.g. a transaction advisory lock within the proposed routine),
not separate SDK calls pretending to be atomic. A lock acquired only when writing
does not protect the earlier Python history read: the commit routine must also
validate the scoped input revision and reject stale bundles for reload/recompute,
or a scoped direct-connection transaction must hold the lock across the history
read and Python computation. Choose one reviewed protocol; an advisory lock alone
does not solve this race. Durable asynchronous processing
and unbounded delayed correlation would require additional design.

The existing org/time index supports bounded history scans. An index on
(organization_id,actor_identifier,event_time DESC) is a useful targeted performance
addition, not required to preserve schema correctness. No other indexing change
is justified by this capture alone.

## Implementation implications and review outcome

Use the file layout in the Phase 2 integration plan, replacing its unverified
mapping placeholders with the contracts above. persistence DTOs must distinguish
occurrence time, detection time and receipt time, omit GENERATED ALWAYS identity,
map score names explicitly, and preserve explanations in JSONB without inventing
columns. Existing pure detection/correlation/scoring code can remain; the service
layer supplies durable IDs, scopes, versions, normalized source identities and
exactly-once effects via transactional idempotency. Current single-event synthetic
API remains no-write and development-only.

Read/review the mapping before approving any implementation or database change.
Critical blockers are permission cleanup and missing DML/SELECT rights, withheld
authorization helper semantics, trusted machine-to-tenant authorization, and
transactional risk-subject validation. Required idempotency behavior is achievable
without new columns if the deterministic single-writer contract is accepted.

All conclusions here are offline analysis of the saved capture. No remote SQL,
migrations, Phase 2 implementation, deployment, commit or push occurred. Phase 1
regression results in the prior plan (38 passes) are historical; tests were not
rerun for this documentation-only change. No runtime RLS/permission test was
performed, so inherited rights and actual enforcement remain a review gate.
