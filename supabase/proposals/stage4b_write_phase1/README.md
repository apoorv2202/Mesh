# Stage 4B-write Phase 1 — local candidates, NOT execution-ready

Recovered from the interrupted session: audit permissions, reference integrity,
human triage, machine support template and machine generator. The generated
machine SQL and offline suite were missing. Existing unrelated Git changes are
not attributed to that session. Original Migration 02 and historical evidence
are preserved. No database connection or SQL execution is part of preparation.

## Proposed order and permissions

1. `01_audit_permissions.sql`: revoke effective API audit INSERT/UPDATE/DELETE,
   TRUNCATE/REFERENCES/TRIGGER/MAINTAIN; preserve SELECT and managed memberships.
   Abort on inherited residual rights or column ACL drift.
2. `02_reference_integrity.sql`: generated finding/incident risk subject columns
   and tenant composite FKs; incident assignee must have same-org membership.
   Existing invalid references abort validation; no data cleanup is implicit.
3. `03_machine_writer_r2.sql`: replaces, rather than accompanies, original 02.
   Dedicated real LOGIN bound by OID and name to one enabled tenant; no passwords,
   LOGIN creation or bindings supplied here. Backend group gets only bounded API
   execution. NOLOGIN/NOBYPASSRLS function owner gets scoped SELECT, column INSERT,
   identity sequence USAGE and private receipt access. Every new object/link is
   audited atomically. Configuration and organization SHARE locks protect scope.
4. `04_human_triage.sql`: authenticated gets EXECUTE only on four fixed wrappers
   in new `vader_user_api`; no direct authenticated writes. Private NOLOGIN owner
   gets only finding status/remediation/resolved_at and incident
   status/assigned_to/resolved_at UPDATE, scoped SELECT, receipts and audit INSERT.
   Guard derives actor from auth.uid(), checks and SHARE-locks active organization,
   active Security Team actor and any new assignee. Existing membership helper
   also remains in RLS. Row UPDATE locks plus expected-state tokens detect stale
   updates. Actor/org/operation/request receipts reject changed-payload replays.

| Operation | Authorized principal | Fields / behavior |
|---|---|---|
| Event append | Tenant backend LOGIN | source/external ID/type/actor identifier/IP/time/details; server tenant/ID/defaults |
| Finding append | Tenant backend LOGIN | source event/title/description/type/severity/evidence; no status/asset mutation |
| Incident append / link | Tenant backend LOGIN | title/description/severity/risk/confidence/summary; tenant-checked event links |
| Risk append | Tenant backend LOGIN | finding or incident subject, score/confidence/factors/explanation/version; immutable input-revision identity |
| Finding triage | Active same-org Security Team | proposed status/remediation; server resolved_at |
| Incident triage | Active same-org Security Team | proposed status/assignment; server resolved_at |
| Normal DELETE / arbitrary patches | Nobody | No entry point or grant |

Owner/HR/developer status alone grants no human write authority. User-editable
metadata never grants membership. Real verified JWT/API tests are separate from
SQL-role simulation. Exposing the user API schema requires later configuration
review; machine/private schemas must never be exposed to PostgREST.

## Integrity and deterministic retries

Existing asset and event/incident-link composite FKs are retained. Machine input
does not permit asset_id, actor_user_id, assigned_to, status or caller IDs; actor
identifier remains an untrusted upstream string, never an Auth identity. First
release accepts only finding/incident risk subjects. Legacy identity/asset risk
rows remain outside these new FKs and must be inventoried before broader support.
Assignee FK protects tenant membership existence; the RPC additionally protects
active Security Team eligibility. It does not prohibit later offboarding.

Machine UUIDv5 identities retain the original typed JSON recipes: org +
source/external ID; source-event/type/detector version; ordered-event chain and
correlation version; risk subject/input_revision/model_version; bundle request
key. Receipts require exact JSONB payload equality. New risk input revisions
INSERT new immutable rows; reusing a revision with changed payload conflicts.
Heuristic version fields are not AI functionality. Incident numbers are sequence
identities, not idempotency keys; sequence gaps after rollback are expected.
Receipts and domain changes/audits share a transaction. Exact replay emits no
second audit. Failed attempts cannot leave an audit inside an aborted transaction;
future backend logging must handle sanitized failure telemetry separately.

## Review blockers — NO-GO for database execution

* Proposed status graph is NOT approved business policy: finding open →
  investigating → remediating → resolved; incident detected → triaged →
  investigating → contained → remediating → recovering → resolved; bounded false
  positive/reopen paths. Same-state remediation/assignment edits are permitted,
  including legacy accepted_risk findings. Review those semantics explicitly.
* Assignment unassignment, offboarding/reassignment and membership hard-delete
  blocking require approval. Existing inactive assignments are not auto-cleared.
* Audit retention/redaction, administrator mutation, unsafe future default ACLs
  and organization cascade deletion remain unresolved. This is atomic audit
  insertion, not tamper-proof retention. No retention DELETE is implemented.
* Current foreign-key prerequisite checks validate names/tables/validation, not
  complete column/action definitions. A guarded future launcher must compare full
  reviewed catalog definitions before apply, including all existing tenant FKs.
* Actual CREATE ROLE, ownership transfer, helper creation, RLS locks, sequence
  permissions, extension placement and direct-login pooler support are untested.
  Never broaden managed role memberships to force success.
* Review managed public/extensions USAGE grants inherited from original 02 and
  PostgreSQL function ownership/EXECUTE/default ACLs with actual runtime assertions.
  All security-definer objects have fixed pg_catalog,pg_temp paths and qualified
  application references; privileged locking helpers are deliberately postgres
  owned and API-inaccessible. Runtime verification must prove that restriction.
* The test_ref setting is a closed review gate, NOT cryptographic project identity.
  No network launcher is supplied. Before any execution, separately authorize a
  pinned TEST-only TLS verify-full launcher with session-user/host guards. These
  SQL files must never be run against production.
* SQL has not been compiled or executed. Offline model tests specify intent;
  they cannot prove PostgreSQL semantics, policies, deadlocks or API authentication.

## Future disposable validation and rollback

First obtain explicit review decisions above. Build a separately approved
rollback-only TEST runner with pinned hashes and baseline assertions. Strip the
outer BEGIN/COMMIT only in a separately reviewed derived test wrapper; never nest
these complete migrations in an outer transaction and assume COMMIT is harmless.
Test migration aborts, inherited/column ACLs, function owners/EXECUTE/search paths,
cross-tenant references, concurrent principal disable/offboarding, stale updates,
replays and audit fault injection. Capture expected catalog deltas separately;
never replace the trusted baseline. Verify fresh cleanup and metadata restoration.
Sequence allocation is nontransactional; cleanup comparison must distinguish
sequence values from definitions. Real LOGIN and JWT/API tests need separate
authorization. No actual runtime runner is provided or executed here.

Before any future committed deployment capture exact ACL/object rollback state.
An apply error must roll back its atomic migration with ON_ERROR_STOP. For a
committed deployment, disable new entry-point execution first, retain receipts
and audits, assess dependency/data safety, then review explicit reverse DDL and
exact previous ACL restoration. Do not use CASCADE, delete history, regrant broad
unsafe rights blindly, or remove validated FKs before a security review.
