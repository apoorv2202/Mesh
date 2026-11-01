# Stage 4B-write Phase 2 rollback harness — PREPARATION ONLY / NO-GO

Current local state: **eligible, execution unauthorized**. See GATE_ELIGIBILITY_REVIEW.md
in the proposals directory. Preparation validation now accepts authorizable=true
only with literal false database/manifest execution-authorization flags and the
approved contract binding. Earlier closed-gate descriptions below are preparation
history, superseded for eligibility only. Runtime and CleanupCheck still require
their separately supplied explicit approval switch and exact reviewed manifest
hash. No launcher or SQL change was made, and no execution is authorized here.

2026-10-31: lifecycle-contract approval is recorded in
`../../../proposals/stage4b_write_phase2/LIFECYCLE_APPROVAL.md`, bound to the
unchanged CONTRACTS.md SHA-256. This supersedes earlier pending-lifecycle-review
wording only. Database execution is NOT authorized. `authorizable` remains false;
the launcher, SQL, assertions and evidence handling are unchanged. See the approval
record for the exact local change inventory. Fresh review and separate execution
authorization are still required; these preparation pins do not unlock runtime.

TEST only: ikmzxirldivefebgxzaa. Production is excluded. No database was contacted.
No grants, migration or SQL have been executed. The new runner was not invoked.

## Contracts and candidate files

See `../../../proposals/stage4b_write_phase2/CONTRACTS.md` for explicit transitions,
assignment/offboarding, audit retention and authorization contracts. These are
proposed first-release decisions, awaiting review rather than deployment approval.
Phase 2 candidates are separate from Phase 1; no historical pins were regenerated.
2026-10-31 blocker corrections are documented in BLOCKER_CORRECTIONS.md under
the proposals directory. The preceding Phase 2 preparation manifest is archived;
only this local preparation revision receives updated pins.
`build_candidates.py` derives four full migration candidates and four transaction-
free `.body.psql` includes using exact source anchors. Public schema and existing
helper/extension EXECUTE grants remain unchanged. Only extensions USAGE is added
for vader_writer_owner, with no CREATE/grant option or PUBLIC grant. Triage adds a private monotonic target revision to
prevent ABA stale-token reuse, and blocks terminal edits without explicit reopen.
Inactive existing assignees must be cleared or replaced before later mutations.

## Scope and expected checks

| Case | Expected result | Tier |
|---|---|---|
| Same-tenant Security Team finding/incident lifecycle | Success with atomic receipt, revision and audit | rollback SQL role |
| Closure, reopen, false positive, self-assignment/unassignment | Allowed only by explicit graph | rollback SQL role |
| Foreign org / foreign assignee | 42501 | rollback SQL role |
| Foreign risk subject or assignee composite FK | 23503 | rollback SQL role |
| Owner/HR/developer, pending/suspended/offboarded | 42501 | rollback SQL role |
| Missing identity | 42501 | rollback SQL role |
| Caller severity/arbitrary field patch | 22023 | rollback SQL role |
| Same request/payload | Exact response, no second mutation | rollback SQL role |
| Same key with different payload | 22000 | rollback SQL role |
| Old state token | 40001 | rollback SQL role |
| Audit INSERT fault | 42501, no domain/revision/receipt/audit residue | rollback SQL role |
| Backend bound LOGIN / principal disable / fresh risk revision | Valid only for real session_user | later separate tier |
| Concurrent offboarding/update, stale writers, receipt contention | Lock ordering/serialization behavior | later separate tier |
| Real JWT signature/claim tampering/API schema exposure | Membership authorization with verified gateway | later separate tier |

The prepared SQL expects 46 human lifecycle/replay/reference/column assertions,
20 membership/missing-identity denials, two FK failures and one audit fault case.
These are future assertions, NOT completed runtime results. Machine positive
writes cannot be simulated with SET ROLE: machine_scope authenticates session_user.
Creating and rolling back new roles prevents other connections seeing them. The
metadata-protection table locks also preclude multi-connection concurrency tests.
Do not claim full write PASS from this tier. Concurrent races are modeled offline
only until separately approved multi-connection testing prerequisites exist.

## Transaction, collisions and metadata

`runtime.sql` has one BEGIN, savepoint and final ROLLBACK, with no COMMIT. The only
proposal includes are generated bodies with the outer BEGIN/COMMIT removed and
byte-compared against their full candidate sources offline. ON_ERROR_STOP ensures
any unexpected SQL error terminates psql and disconnect rolls back pending work.
No exception catches suppress harness assertion failures. Expected failure probes
are isolated in PL/pgSQL exception subtransactions and require the precise SQLSTATE.

Collision checks reuse the original read checks and add global probe UUIDs, audit
organization residue, all new roles/schemas/FK names/generated fields. Fixtures use
the same two existing reviewed Auth identities, global fixed child UUIDs and
negative incident numbers; no Auth writes and no nextval. Failed test statements
are within the rollback scope. Neither full migration files nor runtime includes
provision actual LOGINs or credentials.

Original metadata format, expected MD5 90a71db3b16ed177b3455f61a59343b2 and the R2
temporary-namespace normalization remain unchanged. All persistent old native rows
must survive exactly, except approved audit and sequence ACL changes. Added
inventory is closed: 3 roles, 3 schemas, 16 functions, 20 policies, 20 constraints,
8 indexes (5 private + 3 TOAST), 40 FK triggers, 15 private/TOAST relations and two
generated public columns. The PostgreSQL deparser/TOAST counts are explicit
fail-closed assumptions pending actual PG17 compilation/testing, not a discovered
live-state result. No unrelated object delta is permitted.

`assert_integrity.sql` checks all eight existing/new tenant FK contracts, generated
risk expressions, ordered child/parent columns, match/actions and validation/
deferral settings. `assert_permissions.sql` checks each public column's effective
privileges for new roles, all API mutation denials, fixed function owners/search
paths/definer mode/EXECUTE and sequence use. `assert_delta.sql` preserves existing
RLS/functions/constraints/indexes/defaults/event triggers and managed memberships.
Full public columns are compared independently before/after rollback. Native
relationships are preserved exactly. assert_memberships.sql permits exactly six
PG17 creator edges for the three new roles and trusted postgres operator: bootstrap
ADMIN-only and postgres-granted INHERIT/SET-only. Any other edge/options/grantor,
or change to a pre-existing edge, fails closed.

assert_acl_exact.sql compares complete explicit ACL tuples captured before/after:
all public/private tables, columns and sequences; public/extensions/new schemas;
and new private/API functions. This includes column SELECT without table SELECT,
all grantors/grantees and every grant option. Existing native functions/other
managed schemas remain under unchanged historical metadata assertions. The oracle
retains every baseline tuple except the exact audit revocations and adds only
145 reviewed tuples. It rejects extra grants even on otherwise approved objects.
Exact ACL comparison runs before fixtures and after probes. Full rollback must
match the original tuples; fresh cleanup requires the recorded pre-attempt ACL
fingerprint from hash-verified attempt evidence. Missing original evidence stops
cleanup for separate investigation; it does not invent a successful restoration.

## Execution and evidence design

Do not run either command now. Eligibility alone does not authorize either command.
After review corrections, independent re-pinning and separate explicit approval,
the intended commands, from the repository root, are:

```powershell
& .\supabase\testing\ikmzxirldivefebgxzaa\stage4b_write_phase2\Invoke-WriteRollback.ps1 -Action Runtime -ApproveTestRollback -ReviewedPinsSha256 '<independently-reviewed-new-pins-sha256>'
& .\supabase\testing\ikmzxirldivefebgxzaa\stage4b_write_phase2\Invoke-WriteRollback.ps1 -Action CleanupCheck -ApproveTestRollback -ReviewedPinsSha256 '<same-reviewed-pins-sha256>'
```

The launcher accepts no host/user/database override. It clears/restores PG*
environment variables, uses the fixed TEST pooler username/host, TLS verify-full,
reviewed CA certificate, psql -X -W and an interactive terminal. No secret is stored.
The SQL guard verifies exact TEST routing/operator/version and mapped synthetic
users. Pooler credentials route the project; no pretend server-side project oracle.

Evidence is create-once under the new `evidence/` directory: runtime.txt,
runtime.stderr.txt, runtime.receipt.json; separately cleanup_check equivalents.
Exit status is checked before result parsing, stderr is preserved and hashed,
and exactly one rollback acknowledgement plus all expected assertions are required.
The launcher neither retries nor invokes cleanup automatically. Fresh cleanup is
mandatory in a separate connection, also after failures if separately authorized.
It checks original trusted metadata, original target columns, absence of fixtures,
temporary grants, roles, schemas, generated fields and new constraints. A failed
run is never reclassified as PASS because cleanup later succeeds.

## Remaining blockers and recovery

NO-GO for execution pending contract review, another independent assertion/hash
review, PG17 syntax/deparser assumptions and Supabase compatibility. Local tests
cannot prove function compilation or Supabase managed event-trigger behavior.
The candidate is eligible in execution_readiness.json; database execution remains
unauthorized in both readiness and preparation metadata. A future invocation must
still receive separate explicit approval and the exact newly reviewed manifest hash.

On unexpected runtime error: stop, preserve stdout/stderr/receipt, no retry. psql
connection close rolls back. Run only the separately authorized fresh read-only
cleanup and investigate any mismatch. Do not run manual cleanup DELETE, CASCADE,
schema drops, baseline replacement, managed role grants or production commands.
No committed deployment/retention rollback is authorized by this harness.

Offline negative validation uses acl_negative_tests.py and acl_model.py. Unexpected
column/table/private reads, PUBLIC/schema access, every ACL grant-option class,
wrong grantors, missing approved grants, incorrect creator relationships and
incomplete rollback are mutated in memory and must be rejected. These tests do
not execute PostgreSQL grants and cannot prove PostgreSQL catalog behavior.
