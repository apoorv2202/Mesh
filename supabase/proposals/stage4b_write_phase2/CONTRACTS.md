# Stage 4B-write Phase 2 proposed contracts

Local design only. TEST ikmzxirldivefebgxzaa. No database execution authorized.
Phase 1 proposals and pins remain unchanged; Phase 2 derives separate candidates.

## Human status transitions

Only an active, same-organization Security Team member may invoke triage. Owner,
HR and developer roles do not inherit this authority. Every mutation requires a
nonempty bounded reason, actor-scoped request key and current state token.

| Kind | From | Permitted next states |
|---|---|---|
| Finding | open | investigating, false_positive |
| Finding | investigating | remediating, false_positive |
| Finding | remediating | resolved |
| Finding | resolved, false_positive | investigating (explicit reopen) |
| Finding | accepted_risk | none; separate future acceptance policy required |
| Incident | detected | triaged, false_positive |
| Incident | triaged | investigating, false_positive |
| Incident | investigating | contained, false_positive |
| Incident | contained | remediating |
| Incident | remediating | recovering |
| Incident | recovering | resolved |
| Incident | resolved, false_positive | triaged (explicit reopen) |

Same-state edits are allowed only in nonterminal workflow states and must change
remediation or assignment. No terminal-state edits without reopening. No direct
open-to-resolved, backward phase skipping, DELETE or acceptance of risk. Closure
sets resolved_at on the server; reopen clears it. Existing machine evidence and
severity/risk scores remain immutable. Finding remediation is bounded plain text,
not executable content. Request reason is not an arbitrary metadata container.

Private per-target revision numbers are added to state tokens to prevent ABA
(a return to the same visible fields must not revive an old token). Target row
locks serialize mutations; revision/audit/receipt/domain changes are atomic.
Exact request replay returns the original result only after current authorization
is rechecked. Different payload under the same key fails 22000; stale state fails
40001. Retry 40001/deadlock/timeout only with a fresh state and a new request key
after inspecting the result; callers must not silently change a prior key payload.

## Assignment and offboarding

assigned_to may be NULL or an active Security Team member of the same organization,
backed by a composite membership FK and existing auth.users FK. Explicit NULL
unassigns; same-tenant authorized humans can reassign with reason/state token.
No assignment is inferred from actor strings or JWT user metadata.
Actor and new assignee memberships, organization status and machine binding are
SHARE locked through the write transaction. Status/role offboarding UPDATE must
wait for an already authorized transaction or win first and cause denial.
An offboarding committed before authorization always denies the write/replay.
There is no claim of immediate cancellation of already authorized transactions.

Offboarding does not rewrite historical assignees. A subsequent incident mutation
must clear/reassign an inactive assignee; closing is not an exception. Membership
hard deletion is blocked while assignments reference it. No automatic reassignment
or organization deletion is included. Concurrent offboarding with incident updates
must be tested in separate connections before release; no bulk membership-plus-
incident operation with inverted lock order is approved.

## Audit contract

Retain successful write audit records indefinitely in first release. No purge,
retention DELETE RPC, user redaction UPDATE or normal organization deletion is
authorized. A future retention period requires a separate legal/product decision
and reviewed export/purge design. Existing organization ON DELETE CASCADE means
administrator deletion can still erase audit rows: administrator/tamper-proof
retention is NOT established by these proposals. Do not advertise that guarantee.

Revoke API audit INSERT/UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER/MAINTAIN, including
effective and column privileges; preserve existing SELECT/RLS. Machine/triage
owners receive column INSERT only, scoped RLS and no audit read/update/delete.
Audit trigger/constraint errors abort the operation including receipt/revision.
Exact replay does not duplicate audits. Failed-operation telemetry cannot survive
inside an aborted transaction; a separate sanitized backend security log is needed.
Metadata contains actor or backend principal, operation version, request ID,
target, state tokens/status/assignment and bounded reason; never full payloads,
credentials, upstream details or remediation text. Reason must prohibit secrets
and unnecessary PII at the application boundary. No log retention automation here.

## Integrity / role contract

Existing tenant composite FKs are asserted by ordered column arrays, parent table,
referenced columns, validation, match mode, actions and deferral flags. Added risk
finding/incident FKs are NO ACTION and nondeferrable; generated columns must match
their exact subject-type branches. Asset and identity risk are rejected by machine
input; legacy rows remain unmodified. Backend cannot set assets, auth actor UUID,
assignment, org, timestamps/defaults, triage state or audit fields arbitrarily.

Dedicated backend LOGIN maps OID+name to one enabled tenant, with vader_ingest as
its only membership and no privileged/SET ROLE escape. Never grant writer owner.
SECURITY DEFINER entry functions have NOLOGIN NOBYPASSRLS owners, fixed search_path,
qualified object names and private helper EXECUTE closed to API roles. Narrow
postgres-owned read/locking helpers are part of the trusted computing base.
Existing managed role memberships, helpers, event triggers and default privileges
are not changed. Only public USAGE is inherited from PUBLIC. The writer owner
receives explicit extensions USAGE for UUIDv5/digest lookup, without CREATE or
grant option. Existing extension function ACLs must already allow EXECUTE; no
PUBLIC or native helper-function grant is added. This one native schema ACL
addition is included in the exact ACL oracle and rollback/fresh-cleanup comparison.

Provisioning sets transaction-local createrole_self_grant='set,inherit' only for
creation of the three new roles. PostgreSQL 17 creates TWO memberships per role:
bootstrap grantor OID 10 -> postgres with ADMIN true, INHERIT/SET false; and
postgres grantor -> postgres with ADMIN false, INHERIT/SET true. Role IDs must be
one of the three newly created VADER roles; no old edge may change. SET allows
owner transfers, while INHERIT permits owner-authorized ACL grants/revocations.
Capability checks precede ownership transfer; function ownership is checked after.
The resulting six edges are exact assertions, not a wildcard exemption. Both
roles and memberships disappear on rollback. Existing postgres/Supabase role
attributes and relationships are never altered. Creator GUC changes are local
to the transaction. This provisioning relationship is for the trusted operator,
never a backend login, API role or application user.

## Rollback-only test boundary

The prepared first harness tier tests transactional DDL, exact permission deltas,
human SQL-role triage and reference failures using existing synthetic Auth UUIDs.
No managed Auth writes, passwords, new LOGIN provisioning or sequence nextval.
Roles created in an uncommitted transaction cannot authenticate from another
connection. Therefore genuine backend LOGIN/pooler and multi-connection concurrency
cannot be proven by this first rollback-only tier. Do not spoof session_user to
claim machine-authentication success. Real JWT/API is also a distinct future tier.

These are proposed contracts for review, not approved deployment policy. Execution
requires a separate explicit authorization naming the reviewed pins and scope.
