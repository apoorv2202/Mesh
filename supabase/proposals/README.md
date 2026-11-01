# VADER database security proposals — not approved or applied

These files are deliberately outside `supabase/migrations/`. Do not run them
against MESH production. No Python persistence is implemented. The migration
files have explicit closed review guards and are design candidates, not validated
release artifacts. Approval flags are accidental-run guards, not security checks.

See `FINAL_REVIEW.md` for the latest user-confirmed verification findings,
necessary preflight revisions and per-migration decisions. It supersedes older
missing-evidence statements below only for the facts explicitly confirmed;
unreported helper settings and runtime behavior remain unverified.

## Files and evidence

* `01_vader_security_hardening.sql`: targeted privilege revocation plus residual
  effective-privilege assertions. Does not alter existing authorization helpers
  or grant frontend writes. Does not yet enable frontend SELECT.
* `02_vader_transactional_writer.sql`: two new NOLOGIN roles, private tenant
  bindings and replay receipts, private/API functions, owner-scoped RLS policies,
  sequence access and typed generated-column risk FKs. No login or tenant binding
  is enabled by this file. No extension installation or guessed existing table.
* `../inspection/verify_vader_effective_privileges.sql`: proposed read-only
  effective privilege, membership, helper-settings and sequence checks. Not run.
* This file: assumptions, identity contract, rollback and disposable tests.

Evidence is the saved `mesh_inspection.json` and
`docs/database/vader-schema-mapping.md`, not a new live connection. The export
contains 18 tables, all RLS-enabled/non-forced, with postgres as owner. All five
target tables directly grant TRUNCATE, REFERENCES, TRIGGER and MAINTAIN to anon,
authenticated and service_role. PUBLIC/schema USAGE means schema access is
already established; the dangerous table grants are not neutralized by lacking
USAGE. The direct grants establish a usable SQL privilege path without needing
inherited rights. Foreign-key restrictions can make an isolated TRUNCATE fail;
that does not make the grant safe. This is not proof that REST exposes TRUNCATE.

**Cannot finish an effective-rights audit from this export:** role attributes,
transitive membership options and effective privilege function results were not
captured. Direct ACL absence does not prove absence of inherited DML/SELECT.
The follow-up inspection uses has_table_privilege, has_schema_privilege and
pg_has_role MEMBER/USAGE/SET, including PUBLIC and ownership effects, rather than
guessing. No remote SQL was executed to resolve these gaps. Any claim that all
effective privileges have already been verified would be false.

Correction/clarification to earlier mapping limitations: section 11 DOES contain
the sequence ACL for `public.security_incidents_incident_number_seq`, with only
postgres SELECT/UPDATE/USAGE. Sequence ownership and effective inherited access
still need checking. The proposal grants only USAGE to the restricted owner.

## Minimum permission scope

Revoke only unnecessary powers on the five VADER persistence tables and prevent
frontend DML. Never grant ALL or disable RLS. The hardening proposal asserts that
the dangerous powers are no longer effective; if a parent role, ownership or
PUBLIC path preserves them, the whole transaction aborts. Analyze that path and
review a focused membership/grant change rather than blindly revoking managed
role relationships. Cross-application rights on the remaining 13 tables require
a separate audit; this targeted proposal does not claim to fix the entire app.

Default ACL changes are NOT applied globally by these files. Postgres-creator
defaults repeat the non-DML grants; supabase_admin defaults grant broad table DML.
Changing defaults affects future public tables for that creator across MESH.
Inventory both global and public-scoped defaults and add separately reviewed
creator-specific changes if warranted. A public-scoped revoke cannot subtract a
global default grant. Test new-object ACLs in disposable tests and require a
privilege check in the future migration process. No schema CREATE is granted to
API or machine login roles.

Authenticated SELECT can be approved later for the five existing SELECT policies
once is_mesh_member is verified. VADER ingestion does not depend on frontend
reads; withholding this grant avoids exposing rows through an unreviewed helper.
No service-role table DML grant is proposed. BYPASSRLS and table grants are
separate; service_role must not become the normal tenant boundary.

## Authorization helper review still required

All three exported bodies were WITHHELD, not reviewed:

| Routine | Known metadata | Required private verification |
| --- | --- | --- |
| is_mesh_member(uuid, mesh_role[]) | postgres-owned SQL STABLE SECURITY DEFINER; authenticated EXECUTE | auth.uid binding, organization equality, active status, roles/owner override semantics, NULL handling, defaults, safe search_path, recursion and underlying table access |
| handle_new_mesh_user() | SECURITY DEFINER trigger function; PUBLIC EXECUTE; attached to auth.users INSERT | profile provisioning and whether user-controlled metadata can grant memberships/roles; safe schema resolution and minimal ownership |
| rls_auto_enable() | SECURITY DEFINER event-trigger function; PUBLIC EXECUTE | actual event-trigger registration/status, command filters, safe identifier quoting, handling of managed schemas and effect on new proposal objects |

Do not reconstruct helper bodies from policy names or replace them with guessed
SQL. Trigger functions cannot simply be invoked as ordinary scalar functions;
PUBLIC EXECUTE still deserves review, not an automatic claim of exploitability.
Do not set search_path on existing functions blindly: verify qualified names and
behavior first. Review routine default arguments/settings privately for secrets.

## Chosen writer trust model

The proposal requires **direct database sessions with a dedicated per-tenant
LOGIN**; `session_user` is the authentication root even inside SECURITY DEFINER.
It is intentionally NOT a Supabase SDK/PostgREST RPC design: session_user would
be authenticator for API traffic, and a caller-set JWT/GUC is not a replacement.
PgBouncer/Supavisor must preserve the authenticated database role and one explicit
transaction; otherwise use a supported direct/session connection or redesign.
Do not map a generic postgres, authenticator or global service login.

An administrator would separately create a secure LOGIN, without superuser,
BYPASSRLS, CREATEROLE or CREATEDB; grant only the execute-only vader_ingest role
with inherited access and no admin/SET escalation; then bind its OID+name to one
organization in vader_private.principals. No credential appears in these files.
Use one enabled binding per login; disabling it revokes future function access.
Never grant membership in vader_writer_owner, nor rights on binding/receipt
tables, to a caller. The function rejects extra transitive role memberships.
Audit direct grants too: membership checks alone do not detect directly granted
table rights or arbitrary SECURITY DEFINER EXECUTE paths.

vader_writer_owner is NOLOGIN, non-superuser and NOBYPASSRLS. It receives only
SELECT/INSERT on the five application tables and scoped RLS access; no UPDATE,
DELETE or ownership of application tables. Private receipt UPDATE is limited by
RLS and inaccessible to callers. Only temporary CREATE on the two new schemas is
used to transfer function ownership, then revoked. Functions use trusted catalog
search paths and fully qualified application objects. Schemas are not exposed to
PostgREST. Existing read policies are not rewritten.

The database authenticates tenant scope; it does not establish upstream signal
truth. A compromised authorized worker can fabricate findings within its tenant.
Only reviewed backend computation may call this interface. Organization fields,
arbitrary IDs, status changes, assignment, enrichment and unknown keys are not
accepted in entity objects. A role bound to tenant A cannot switch session_user
to tenant B without a genuinely privileged database capability.

## Transaction and input contract

On one dedicated connection:

1. Begin a transaction with bounded lock/statement/idle-in-transaction timeouts.
2. Call vader_api.read_history_v1(actor, from_time, to_time). It authenticates the
   login, locks the tenant for the transaction and returns at most 1,000 events
   and a canonical SHA-256 revision. Maximum requested history is 120 minutes.
3. Combine this history with normalized incoming events in memory and run the
   existing Python engines. No Python changes are included here. Source occurrence
   time and canonical actor namespace must remain stable across delivery retries.
4. Call commit_bundle_v1 with request_key, actor, history bounds/revision and the
   four required arrays: events, findings, incidents, risks. Each array is bounded
   to 100 items and the bundle to 1 MiB. All incoming/matched events must fit the
   history bounds; four-stage chains must be strictly ordered within 60 minutes.
5. Commit before acknowledging success. The function does NOT issue COMMIT.
   An HTTP response/function return before outer COMMIT is not durable success.

The writer repeats the history revision check under the lock. If read_history
was accidentally used in autocommit, intervening compliant writes invalidate the
revision and produce SQLSTATE 40001 rather than accepting stale correlation.
The history/actor window must cover every candidate chain, including late-arrival
lookahead; define bounded lateness and reject/defer outside it. This proposal
does not guarantee detection of history outside the explicit requested scope.
Tenant-wide locking is conservative: distinct tenants can run concurrently;
workers within one tenant serialize. Measure contention before narrowing locks.
Direct administrative/legacy writers that bypass the protocol are out of contract.

No dynamic table/column SQL is accepted. INSERT columns are static and generated
incident_number/timestamps are omitted. SQL record casting normalizes input types;
event-specific counters require nonnegative integral JSON numbers and flags real
JSON booleans. Unsupported risk subjects (identity/asset/event) are rejected.
The backend still validates Pydantic input and calculates risk; the SQL does not
reimplement or independently attest the risk scoring formula.

All five application writes, incident links and receipts are atomic. A failure
at any point aborts them together; SQL exceptions are rethrown with their code
and a generic message so raw key/evidence values do not reach clients. Preserve
operator diagnostics through safe correlation IDs, not raw database exceptions.
Retry transient/unknown-commit outcomes with the same request_key/body. Reload
and recompute after 40001; an actually changed bundle must use a new request_key.
Do not retry permission, payload identity or validation failures indefinitely.

## Deterministic identities

The database is authoritative for UUIDv5 derivation. Fixed namespace:
`95980ed1-c0d3-5b64-90cc-9ea71f7b0385`. Name is PostgreSQL JSONB text of:
`["mesh-vader-storage-v1", kind, tenant_uuid, identity_parts]`.
Keep the version and whitespace/canonical serialization fixed; don't assume
Python json.dumps matches PostgreSQL JSONB text. Before Python integration, make
cross-language vectors or use a separately reviewed scoped identity-planning API.
The private helper is NOT granted to machine callers in this proposal.

| Kind | Identity parts |
| --- | --- |
| bundle | [stable request_key] |
| event | [trusted source, non-NULL external_event_id] |
| finding | [persisted source_event_id, finding_type, evidence.detector_version] |
| incident | [summary.ordered_event_ids, summary.correlation_version] |
| risk | [subject_type, subject_id, factors.input_revision, model_version] |
| incident link | Existing PK (incident_id,event_id) |

UUID inputs use UUID typed canonical serialization. Internal versions/revisions
are supplied by the trusted worker, never the frontend. Versions have no defaults
and must be nonblank. Events require stable source/external IDs; NULL does not
evade the existing partial unique index. Source namespaces must disambiguate
integrations inside a tenant. UUID hashes are identity tools, not authentication.

The private receipt PK enforces a single canonical immutable payload per kind/ID;
same identity with changed payload fails. Full JSONB equality guards hash
collision/payload substitution. Bundle receipts cache committed result IDs to
recover after timeout without resetting triage status, timestamps or numbering.
Per-row replay skips application INSERT and never overwrites current triage.
Incident risk_score/confidence are initial snapshots under this immutable writer.
Later rescoring appends a new risk revision; omit an unchanged existing incident
or reuse its original payload rather than changing the same incident identity.
Updating incident snapshots or triage belongs to a separately authorized workflow.
Receipts contain sanitized evidence and need the same retention/access protection
as original rows; no indefinite deletion policy is assumed. Do not delete receipts
without reviewing retry retention and deterministic-ID reuse behavior.

Legacy preexisting rows have no receipt and may use random IDs. The writer fails
closed on existing PK/natural-key conflict rather than silently adopting unknown
payloads. Before rollout, assess overlap and approve a separate legacy-reconciliation
strategy if needed. Schema inspection contains no application row counts or data.

## Risk subject integrity

The proposal adds two stored generated UUID columns to security_risk_scores and
two composite FKs: (organization_id, finding subject) and (organization_id,
incident subject). These are NEW columns, clearly proposed, not inferred existing
schema. They ensure same-tenant existence for those two kinds, apply to all writers
and block parent deletes that would orphan scores. The writer independently checks
ownership for clearer generic failure and rejects all other subject types.

FK creation validates existing data; existing orphans/cross-tenant links cause the
whole proposal transaction to fail. No NOT VALID rollout or automatic cleanup is
included. Generated columns may rewrite/lock the table and alter SELECT * output;
assess volume, dependencies and maintenance window. Keep subject_id UUID and all
existing range/subject-type checks. Asset/identity polymorphic rows remain outside
this minimum guarantee; other writers must not claim equivalent integrity.

## Rollback and recovery strategy

Before ANY application (including nonproduction), capture current object ACLs,
owners, default ACLs, memberships, policies, function definitions and a tested
backup under appropriate secret controls. Preserve the inspected JSON as evidence,
not as a complete backup. Snapshot prerequisites, not just newly created SQL.

* In test, migration failure rolls back transactional DDL/grants and writes. The
  review guards must fail without leaving created roles/schemas. Test this first.
* After rollout, first disable tenant principal bindings and stop worker sessions;
  revoke entry-point EXECUTE/entry role membership, then wait/terminate only the
  identified worker transactions under an approved operations procedure. Already
  running transactions may finish; disabling a binding does not erase their work.
* Preferred rollback is **disable writer, preserve evidence**. Leave ingested rows,
  tenant FKs and receipts intact. Do not DELETE newly ingested security evidence
  as a rollback and never TRUNCATE application tables.
* If DDL removal is approved, drop entry functions, then helper functions/policies
  in dependency order; retain/archive binding/receipt tables until retry retention
  expires. Remove generated FKs/columns only after accepting lost integrity and
  checking dependencies. Revoke sequence/table/schema rights, remove explicit
  principal memberships, then drop roles only when no owned objects/grants remain.
  Never DROP SCHEMA ... CASCADE, DROP OWNED or REASSIGN OWNED as a blind shortcut.
* Permission cleanup is normally retained. Restoring dangerous TRUNCATE grants is
  not an automatic rollback step. If a legitimate dependency requires a privilege,
  restore only the captured necessary grant via separate security approval.
* Any optional SELECT/default-ACL changes need exact captured inverse grants;
  do not GRANT ALL as a rollback. Empty remote migration history remains a
  separate reconciliation task; these proposal files must not be db-pushed.

## Disposable nonproduction validation checklist

No Docker requirement: use a separately provisioned disposable PostgreSQL 17 or
Supabase test project, with synthetic tenant/user metadata and no production data
or credentials. A plain PostgreSQL database needs faithful Supabase roles/auth
helpers; a real disposable Supabase project is preferred for final RLS tests.
Do not reconstruct production helper bodies from guesses. Review/copy only the
authorized schema dependencies needed for tests; do not recreate managed auth.

- [ ] Obtain helper bodies, role memberships/attributes and event-trigger settings
      privately. Record effective rights before changes; don't confuse role name
      membership with a tenant session. Verify pg_has_role SET paths.
- [ ] Run migration guards closed: both abort with no retained objects/ACL changes.
- [ ] Apply 01 in the disposable DB after explicit review. Check effective dangerous
      privileges are false for API roles, including inherited/PUBLIC paths. Add a
      synthetic inherited TRUNCATE path and show 01 fails/rolls back. Test schema
      USAGE separately; its absence is not considered an adequate revocation.
- [ ] On synthetic tables only, prove a role with TRUNCATE ignores RLS, then show
      denial after cleanup; test FK-related table sets. Never try this on MESH.
- [ ] Review future objects created by postgres/supabase_admin for default-grant
      regressions, without granting global rights to make tests pass.
- [ ] Apply 02; verify new roles NOLOGIN/NOBYPASSRLS, application ownership unchanged,
      limited grants, no schema CREATE left, no PUBLIC/API function EXECUTE and no
      caller table DML. Verify sequence access and identity-number behavior.
- [ ] Provision two distinct synthetic per-tenant LOGIN sessions plus unmapped and
      disabled sessions. Test real authentication, not SET ROLE under postgres.
      PostgreSQL session_user is unchanged by SET ROLE; admin simulations are not
      a proof of this authorization model.
- [ ] Reject same-tenant override attempts, foreign source-event IDs, foreign incident
      event links, and foreign/nonexistent risk subjects. Test direct insertion under
      an authorized maintenance test role too: the new FKs must reject both subject
      cases and parent deletion, regardless of writer checks or RLS bypass.
- [ ] Existing invalid risk references prevent migration atomically; valid legacy
      asset/identity rows remain unaffected. Test generated-column dependencies.
- [ ] Wrong payload keys/types, NULL IDs, booleans/string/fractional counters, bad IP,
      missing timezone, oversized arrays/body, duplicate/unordered/missing stages,
      stale history and history overflow all fail without partial output.
- [ ] Assert exact UUID vectors for each entity, fixed server canonicalization and
      cross-language parity before building Python persistence. One upstream source
      ID with two payloads must conflict; legitimate identical content with different
      upstream IDs must remain distinct.
- [ ] Replay identical bundle after COMMIT/timeouts: IDs/row counts stable; no changed
      status, created_at, detection timestamps or incident_number. Different batch
      keys with shared entity identities dedupe. Changed entity payload fails.
- [ ] Inject failure after event, finding, incident, link and score writes and before
      receipt response update. Assert all application rows and receipts roll back.
      Identity sequences may legitimately have gaps on rollback; do not assert gapless.
- [ ] Two concurrent workers same tenant serialize; different tenants proceed. A
      worker that read history in autocommit gets 40001 after intervening inserts;
      explicit-transaction read/compute/write workflow holds the lock throughout.
- [ ] Test auth helper active/suspended/offboarded, anonymous, wrong tenant, missing
      roles, owner/security-team behavior and hostile search_path/temp objects.
      Security Team SELECT remains denied until the separately reviewed grant.
- [ ] Test log/exception redaction and evidence retention permissions, no browser
      secret exposure, disabled-principal revocation and role drop/recreation.
- [ ] Exercise disable-first rollback and object removal on disposable state. Check
      preserved security evidence and unchanged application tables afterwards.

## Assumptions and approval blockers

1. Saved export provenance/project association is correct; schema has not drifted.
2. PostgreSQL 17 behavior, uuid-ossp functions in extensions, digest function and
   exact identity sequence match the live/test schema; role-creation/ownership
   transfer privileges are available to the approved deployment operator.
3. Actual inherited rights and helper definitions are still missing; follow-up
   inspection must precede any permission or frontend read change.
4. Per-tenant direct-login operation, secure provisioning/rotation, transaction
   pinning and tenant-wide serialization are acceptable. This changes the earlier
   Supabase-SDK transport preference intentionally; it must be approved. If SDK-only
   transport is mandatory, redesign authorization rather than trusting a GUC.
5. No unreviewed direct grants, powerful definer routines or alternate writers can
   bypass the single-writer contract. Administrator access is trusted, not contained
   by this model. Event source provenance and risk algorithm truth remain backend
   responsibilities; SQL validates scope, not independent compromise probability.
6. Legacy row conflicts and risk subject violations have not been inspected. FK
   validation/column storage locks and receipt storage costs require measurement.
7. Machine callers need a reviewed method to derive event/finding/incident UUIDs
   before referencing new rows; fixed PostgreSQL canonicalization vectors are a
   release blocker, not an excuse to expose the private helper broadly.
8. Event windows, maximum batch size, receipt retention and delayed-event policy
   are proposed defaults, not workload-tested production limits.

Validation performed here: offline schema/ACL review and local static SQL checks.
No PostgreSQL engine or SQL/PLpgSQL parser was initially available; unless an
additional validation note is recorded below, syntax/catalog resolution and
runtime behavior remain untested. These are proposals for review, not assurances
that a production migration is safe. No remote SQL, migrations, Python changes,
deployment, commit or push occurred.

References: [PostgreSQL effective privilege functions](https://www.postgresql.org/docs/17/functions-info.html),
[row security and TRUNCATE](https://www.postgresql.org/docs/17/ddl-rowsecurity.html),
[safe SECURITY DEFINER functions](https://www.postgresql.org/docs/17/sql-createfunction.html).
