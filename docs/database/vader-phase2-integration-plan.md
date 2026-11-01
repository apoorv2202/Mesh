# VADER Phase 2 integration plan — awaiting schema evidence

Planning only. Prepared 2026-10-29 for project `khweikfvsnervfuswhon`.
No Phase 2 Python, SQL migrations, remote queries, or deployments were performed.

## Evidence and blocking decision

Inspected the Phase 1 Python modules, tests, README and both inspection scripts.
`supabase/inspection/` contains query definitions, not their executed results.
`supabase/schema_snapshot.sql` is zero bytes. The reported successful live
inspection is accepted as user context, but its output is not available here.
Neither a SELECT projection nor the expected-name inventory proves an actual
database column, enum, FK, index, grant or policy exists.

Consequently, no database column mapping or schema change is approved by this
plan. Do not implement persistence until the evidence gate below is complete.
The five target table names are user-reported, not locally verified definitions.
No Owner/HR dashboards or frontend work is in scope.

### Evidence needed to finalize the mapping

Return the exported `mesh_inspection` JSON from the master query. Its section
values wrap the original `inspection` payload. Preserve empty arrays, NULLs and
all fields. Check for SQL Editor truncation. Needed sections:

| Sections | Decisions they unlock |
| --- | --- |
| 01 | Actual table inventory, project capture context and missing/unexpected tables |
| 02 | Exact destination columns, types, NOT NULL requirements, defaults and generated fields |
| 03–04 | PKs, FKs, tenant consistency, unique conflict targets and query indexes |
| 05 | Allowed event, severity, status and risk enum labels |
| 06–08 | Existing authorization helpers, trigger side effects, routine grants and custom dependencies |
| 09–11 | RLS flags, policy commands/roles, USING/WITH CHECK and grants/default grants |
| 12 | Extension and managed-schema dependencies needed for faithful local validation |

Section 07 remains disabled by default. Review relevant authorization and
tenant-validation routine bodies privately, including search_path and grants.
Provide sanitized definitions if they are required for policy verification;
withheld bodies leave those semantics unverified. Never share credentials or
application/Auth rows. Catalog dependencies do not expose all dynamic SQL.

## Phase 1 behavior to preserve and gaps to address

* `models/security_event.py`: validates organization UUID, four event types,
  actor, UTC time, IP and event-specific details. Details allow additional keys.
  No durable source ID or database row ID exists. Omitted time defaults to now,
  making repeated requests unsuitable as a stable identity without an envelope.
* `detectors/rules.py`: four pure rules return findings with rule code, severity,
  explanation, evidence, organization and actor. Findings do not carry persisted
  event identity or detector version; the integration service must attach them.
* `correlation/engine.py`: tenant/actor grouping, strict order, 60-minute default,
  per-call deduplication and a content SHA-256 chain fingerprint. Returns complete
  event bodies, not persisted event IDs. Semantically identical details with
  different JSON key order can survive its initial model_dump_json deduplication;
  canonicalize at ingestion. Fingerprints are not persistent unique constraints.
* `risk/engine.py`: deterministic score/factors/confidence. It trusts callers to
  supply findings/chains from one scope. Evidence completeness averages findings;
  duplicates with different completeness can change confidence. Validate scope
  and deduplicate inputs before scoring. Confidence is not compromise probability.
* `main.py`: development-only, loopback-only, single synthetic event, no historical
  correlation or authentication. Preserve it as a no-write sandbox. Do not enable
  writes by merely removing the loopback guard or supplying a secret key.

## Mapping contract to fill from actual results

The names below are Python output fields, not asserted database column names.
Every database destination remains **blocked** until inspection evidence arrives.
Use explicit allowlisted DTO mappings, never `insert(event.model_dump())`.

| Source values | Intended reported table | Required mapping verification |
| --- | --- | --- |
| SecurityEvent: organization_id, event_type, actor_identifier, event_time, source_ip, details | security_events | Exact columns, enums, JSON support, actor semantics, timestamp/IP representation, integration/asset requirements and durable identity |
| Finding: rule_code, severity, explanation, evidence, organization_id, actor_identifier; persisted source event identity | security_findings | Event FK/cardinality, possible rule registry FK, required fields/status, severity labels, evidence capacity and conflict key |
| Chain: chain_id, organization_id, actor_identifier, explanation, start_time, end_time, evidence, detection_rules | security_incidents | Whether fingerprint fits any existing key, ID type, lifecycle enum/default, narrative/evidence representation and time range support |
| Ordered chain matched_events resolved to persisted IDs | incident_events | Actual link FK columns, tenant enforcement, uniqueness and any sequence-position field; do not fabricate an ordering column |
| RiskResult: risk_score, risk_level, explanation, contributing_factors, confidence_estimate, confidence_explanation | security_risk_scores | Entity/scope FKs, allowed levels/ranges, JSON capacity, history semantics, scoring version and computed-time support |

Inventory all required destination columns not supplied by these values. Use
verified database defaults for generated fields; do not invent integration,
asset, profile, incident or rule IDs to satisfy FKs. Actor identifiers refer to
observed security principals and must not be assumed to be MESH profile UUIDs.
If `vader_detection_rules` is referenced, review its actual definition and
existing rule registry strategy before any proposed seed operations.

## Intended processing flow

1. Authenticate an integration or user on the backend. Resolve the allowed tenant
   from server-verified authorization state; compare any supplied organization
   against it. Actor identity in an event is not the authenticated caller.
2. Validate a bounded ingestion envelope and normalize a stable source identity,
   UTC timestamp and canonical JSON. Reject mismatched organization, unsupported
   schema versions, oversized/unserializable details and invalid source bindings.
   Treat details as untrusted evidence, never executable instructions.
3. Persist normalized events with a database-enforced tenant-scoped conflict key.
   Return/reuse the existing row identity on a verified duplicate. A repeated
   identity with a different canonical payload is a conflict, not a silent update.
4. Run existing detectors on validated normalized events. Attach persisted event
   IDs and detector version in the service layer, then persist findings once.
5. Read bounded history for that tenant AND canonical actor. Rehydrate validated
   models, maintain a separate event-ID lookup, and run the existing correlator.
   For late arrivals, recompute the interval from arrival event_time minus the
   window through event_time plus the window so later transfers can match too.
   Bound lateness, pagination and batch size; report/reprocess outside the bound
   instead of silently treating an incomplete history as complete.
6. Resolve matched events to IDs without relying on list positions or assigning
   IDs by timestamp alone. Persist incident plus all links atomically. Only link
   events belonging to the same authorized organization. Matches remain candidate
   chains, not confirmed compromise. Distinct terminal transfers retain Phase 1
   semantics unless an explicitly reviewed incident-merging policy replaces it.
7. Rebuild a deduplicated input set for an explicit scoring scope and input
   revision. Call score_risk and persist every explanatory component. Start with
   event-level scores and incident-level scores only if verified schema supports
   both; do not invent an organization/actor risk scope absent from the schema.
8. Acknowledge success after required outputs are committed. A durable accepted
   event with pending processing needs verified durable recovery state before
   returning an asynchronous acceptance response.

## File-by-file implementation sequence (proposed files only)

Paths in this table are relative to `azure/security/vader/` unless stated otherwise.

| File | Planned responsibility and acceptance condition |
| --- | --- |
| docs/database/vader-schema-mapping.md (repository root) | After evidence arrives, record exact source-to-column mappings, required defaults, enum translations, named constraints, conflict targets and per-operation policy matrix. No unresolved mappings before coding adapters. |
| config/settings.py | Validated server configuration; persistence off by default, approved project/URL check, separate development/test/production settings, bounded retries and request sizes. Never log secret-bearing representations. |
| models/ingestion.py | Authenticated ingestion envelope, source identity and stable idempotency input. These are API concepts pending DB mapping, not proposed existing columns. Reject unknown caller-controlled persistence fields. |
| models/persistence.py | Explicit DTOs matching verified schema for all five target tables; encode UUID/time/IP/JSON correctly and validate required/default fields and enums. |
| ingestion/auth.py | Verified token/service identity and tenant authorization dependency. Resolve permitted ingestion roles using inspected authorization semantics, without assuming role labels confer write rights. |
| ingestion/normalization.py | Canonical serialization, stable identity and evidence sanitization/size limits. Preserve source occurrence time across retries. Do not equate equal content to one event when sources can legitimately emit identical events. |
| persistence/client.py | Backend-only Supabase transport, timeouts, request-scoped auth and redacted errors. Avoid shared mutable user sessions. No implicit service-role fallback on denied writes. |
| persistence/repository.py | Typed tenant-required reads/writes and exact verified conflict targets. Validate all related IDs against tenant scope; parameterize queries; paginate history; distinguish duplicate, denial and transient failure. |
| services/analysis.py | Orchestrate normalization, rules, event-ID mapping, correlation and scoring; assert one organization/actor scope before correlation/scoring. Retain pure engine interfaces where possible. |
| services/recovery.py | Durable retries/reconciliation using only verified supported state; conditional on transaction/recovery design. No in-memory queue or background task as the sole persistence guarantee. |
| models/security_event.py | Preserve current engine contract. Add database-independent validation only when needed; keep source/database identity in the envelope. |
| detectors/rules.py | Keep thresholds and explanations; expose a version contract outside result serialization if versioning is approved. Do not replace pure rules with DB lookups per event. |
| correlation/engine.py | Preserve chronology and tenant grouping. Add stable ID-aware adapter tests; any deduplication or fingerprint change needs a version and regression tests. |
| risk/engine.py | Preserve formula. Service supplies scoped/deduplicated inputs; add a scoring-version contract. No cross-tenant findings/chains passed through. |
| api/ingestion.py | Separate authenticated ingestion route with typed responses and strict per-tenant batch limits; no frontend incident/risk write API. |
| main.py | Mount authenticated routes only with explicit persistence enablement; keep synthetic analysis no-write. Health responses disclose no secrets or connection strings. |
| tests/test_persistence_mapping.py | Schema-fixture mapping, enum/required-field coverage, serialization and immutable idempotency semantics. |
| tests/test_ingestion_security.py | Invalid/expired/wrong-audience tokens, tenant spoofing, unauthorized role, forged FK IDs, concurrent tenant requests, oversized payloads and credential-safe errors. |
| tests/test_persistence_recovery.py | Concurrent duplicate delivery, timeout after commit, failure at every write boundary, retry exhaustion, restart recovery, late events and stable incident/score identity. |
| tests/integration/test_tenant_isolation.py | Disposable nonproduction DB checks of actual RLS, grants and FK behavior with separate tenant identities; mocks cannot prove isolation. Requires separately approved test environment. |
| README.md | Reviewed deployment/auth boundary, secret configuration, idempotency, response guarantees, operational recovery and limitations. |
| requirements.txt | Reuse installed Supabase SDK; change only if the approved auth/transport choice needs an additional dependency. Never embed credentials. |

## Isolation and credential model

Prefer request-scoped user-context Data API access if inspected grants and RLS
permit the intended ingestion role. Verify JWT signature, issuer, audience and
expiry; an organization UUID supplied in the body is not authorization. Existing
membership helpers must be reviewed for membership status, role checks, recursive
policy behavior and SECURITY DEFINER/search_path hazards.

Background ingestion needs an explicitly reviewed machine identity. Prefer a
least-privilege non-bypass database role/policy or restricted write function if
the existing schema supports it. Secret/service-role API keys bypass RLS; simply
using one on a server does not provide tenant isolation. Never assume adding a
tenant filter makes a privileged client equivalent to database enforcement.

For each target table, document SELECT/INSERT/UPDATE/DELETE grants and policy
roles, WITH CHECK for writes, USING for existing rows, and parent-ID tenant
consistency. A table's RLS-enabled flag alone proves none of these. Junction
tables without a tenant column may enforce isolation through both parent joins;
verify actual policy and constraint definitions before deciding a new column is
necessary. Review ownership/BYPASSRLS as well as forced-RLS flags.

Frontend code receives no privileged key, database password or CLI access token.
Keep server secrets in environment/secret storage, outside Vite variables,
source, logs and exception responses. A frontend may submit events through the
authenticated backend only if explicitly authorized; it cannot author detection
results, incidents or scores. Do not reuse interactive CLI credentials in VADER.

References: [Supabase API key security](https://supabase.com/docs/guides/getting-started/api-keys),
[RLS](https://supabase.com/docs/guides/database/postgres/row-level-security),
[database function privileges](https://supabase.com/docs/guides/database/functions).

## Idempotency, transactions and recovery

* Event identity: tenant + trusted integration/source identity + stable upstream
  event ID is preferred. If sources lack IDs, approve a bounded deduplication
  policy explicitly; content hashes alone can merge legitimate identical events.
* Finding identity: persisted event + rule code + detector version. Incident
  identity: tenant + versioned canonical ordered event sequence. Link identity:
  incident + event, subject to actual schema semantics. Score identity: scope +
  input revision + scoring version, or an explicitly designed append-only policy.
  These are proposed logical identities, not assertions of existing columns.
* Unique database constraints are necessary for concurrent retries. Read-before-
  insert alone is racy. A duplicate must be checked against canonical payload
  and scope before its existing identity is reused.
* Separate Supabase SDK calls do not form one transaction. Preferred design is
  one reviewed transactional write function for a bounded analysis bundle, if
  no suitable existing routine is available. Prefer invoker security; if definer
  rights are necessary, restrict execute grants, fix search_path, validate tenant
  authorization and all IDs inside it, and do not trust caller-computed findings
  from untrusted frontend callers. This would be a proposed DB change, not work
  authorized or implemented here.
* If atomic persistence is unavailable, require idempotent stage writes plus
  durable recovery markers/work source. Existing tables may support this; verify
  first. Never claim all-or-nothing semantics across five REST calls. Do not add
  new queues/tables speculatively, delete partially written evidence as rollback,
  or return successful completion with missing incident links/scores.
* Retry bounded transient network/timeouts, throttling and transient server
  errors using exponential backoff/jitter and Retry-After where present. Reuse
  identities after unknown commit outcome. Do not retry authorization, validation
  or immutable-payload conflicts as transient faults. Return redacted stage/error
  classifications and an opaque diagnostic ID, not database credentials/details.
* Recovery must survive process restarts and concurrent workers; determine the
  existing locking/versioning capabilities before selecting its implementation.

## Conditional database changes to evaluate, not execute

No specific missing column, policy, index or constraint is established yet.
After inspection, propose changes only for demonstrated gaps:

1. Tenant-safe parent/child FKs or equivalent enforced constraints/policies for
   findings, risk records and incident/event links.
2. Durable unique keys for the reviewed idempotency identities; payload hashes
   or rule/scoring versions only if required and not already representable.
3. Representation for the full explanation, evidence, confidence and score scope
   if existing columns cannot preserve them faithfully.
4. Least-privilege ingestion grants/policies and restricted transaction routine
   if existing authorization does not support safe writes.
5. Durable recovery/version state if adopting multi-stage writes, and indexes
   matching verified tenant/actor/time history filters and conflict targets.

Any eventual change requires schema mapping review, local migration-history
reconciliation and separate approval. Do not apply a guessed baseline to the
existing database with empty migration history.

## Validation and review gates

Existing regression command:
`.\azure\security\vader\.venv\Scripts\python.exe -m pytest azure/security/vader/tests -q`

Executed with the existing Python 3.13.6 environment outside the sandbox because
Windows TestClient needs an internal loopback socket. Result: **38 passed in
1.14 seconds**, one existing Starlette/httpx deprecation warning. These tests
prove Phase 1 behavior, not remote schema compatibility, RLS or persistence.

Approval sequence: receive complete inspection results; finalize exact mapping
and policy matrix; agree authenticated ingestion and machine identity model;
review any conditional DB changes and transaction/recovery guarantees; then
authorize Phase 2 implementation. No Phase 2 code should begin with unresolved
tenant isolation, persistence identity or schema-mapping blockers.
