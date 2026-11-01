# Phase 2 local contract/harness review — 2026-10-30

**2026-10-31 correction addendum:** the three independent-review blockers now
have local code corrections. See BLOCKER_CORRECTIONS.md for the current results
and changed-file inventory. The original preparation findings below are retained
as context; statements about unchanged extensions ACLs and rejecting all creator
edges describe the previous revision. Historical evidence/baselines remain intact.
Execution remains NO-GO; the runtime readiness gate remains false.

**NO-GO for a TEST database attempt at this revision.** No connection, SQL,
migration, fixture, runtime launcher or new database test has been executed.

## Delivered and changed files

Only two NEW directories were populated:

* `supabase/proposals/stage4b_write_phase2/`: CONTRACTS.md, this report,
  build_candidates.py, build_object_contract.py, source_hashes.json,
  object_contract.json; four revised standalone SQL candidates and four derived
  transaction-free include bodies for audit, references, machine writes and triage.
* `supabase/testing/ikmzxirldivefebgxzaa/stage4b_write_phase2/`: README.md,
  runtime.sql, cleanup_check.sql, guard.sql, collisions.sql, human_tests.sql,
  capture_columns.sql, assert_delta.sql, assert_acl_delta.sql, assert_integrity.sql,
  assert_permissions.sql, generated assert_object_contract.sql,
  Invoke-WriteRollback.ps1, execution_readiness.json, validate_offline.py,
  offline_tests.py and new pins.json.

Phase 1 files and 11 preparation hashes are unchanged. All 53 historical read
pins match; read closure receipts match their runtime and cleanup log hashes.
Original baseline, Migration 02, R2/read evidence, Python VADER and other existing
files were not changed. New pins do not supersede historical pins.

## Contracts resolved as explicit proposals

CONTRACTS.md specifies bounded status graphs, false positives, closure and reopen;
no accepted-risk transition; no terminal same-state edit. Private monotonic
revisions prevent stale-token ABA. Assignment requires active same-tenant Security
Team membership; explicit unassign/reassign is audited. Offboarding blocks future
authorization/replay and waits for prior SHARE locks, without erasing history.
Subsequent mutation must clear/reassign an inactive incident assignee.

Audit first release retains successful records indefinitely, with no normal purge
or mutation. Audit failure rolls back all operation state. Existing parent cascade
and privileged administrator access prevent a tamper-proof retention claim; a
separate retention/export/organization-lifecycle design remains necessary.
These proposals need explicit contract approval before deployment or testing under
new semantics. No unrestricted authenticated CRUD or AI/ML is introduced.

## Permission/metadata review

Revised candidates preserve native schema ACLs and existing helper/extension
EXECUTE ACLs, relying on existing effective access or aborting. The audit candidate
checks inherited/column privileges. The harness asserts ordered tenant FK keys,
parent identities/actions/deferrability/validation; generated risk expressions;
exact effective column privileges; table/sequence ACL tuple deltas and grant options;
function owners/definer/search paths/EXECUTE; 16 exact function bodies, signatures,
language/strictness/volatility and 20 policy role/command identities.

Historical metadata preservation checks continue covering persistent schemas,
native helpers, default ACLs, RLS, policies, constraints, indexes and event triggers.
Public column definitions/ACLs are captured separately. New catalog counts and
TOAST relationships are fail-closed assumptions, not live observations. New policy
expression trees are not independently reproduced offline: their source is pinned,
role/command inventory and preserved old policies are asserted, and behavior is
scheduled for runtime. This distinction is a remaining independent-review item.

## Offline validation results

* 12 Phase 1 memory-only contract tests passed unchanged.
* 9 new memory-only tests passed: transitions/reopen/ABA, denied writes/columns,
  replay conflict, both offboarding orderings, atomic audit failure and receipt
  error handling. Thread locks are models, not PostgreSQL concurrency proof.
* Phase 1 and Phase 2 static validation passed, including recursive SQL include
  inspection, no COMMIT in the execution path, byte-equivalent stripped proposal
  bodies, exact rollback acknowledgement, routing/TLS/readiness guards and pins.
* PowerShell AST parse passed without invoking the launcher.
* PostgreSQL parser packages are not installed. No SQL compilation/execution is
  claimed. The local Python executable emits a location warning but all checks run.

## Remaining blockers / next step

1. Review/approve the explicit status, assignment and indefinite-retention contract.
2. Independently review new SQL/ACL assertions and new pins; validate PG17 deparser
   and TOAST inventory assumptions on the separately authorized rollback tier.
3. CREATE ROLE/ownership transfer and creator-admin membership behavior remain
   unverified. Native membership deltas deliberately abort; do not widen managed
   memberships to force success. Establish a supported execution/provisioning path.
4. A rollback-only transaction cannot expose new roles/schema to other database
   sessions. Therefore direct backend LOGIN/pooler, concurrent offboarding and real
   JWT/API testing need a separately approved later tier, not session-user spoofing.

The prepared first tier is DDL + human SQL-role only. The readiness JSON is false
and the launcher refuses Runtime before connecting. Do not flip it without a new
review and newly approved pins. Exact future command shape and evidence/cleanup
instructions are in the harness README. Fresh cleanup is separate and mandatory;
an error receipt is preserved even if cleanup succeeds. No automatic retry or
cleanup DELETE is authorized. No production action is proposed.
