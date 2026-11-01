# VADER Stage 4: TEST tenant isolation preparation

Revision-2 correction: read `HARNESS_R2_REVIEW.md` before any future execution.
The persistent metadata comparison now omits only system-identified temporary
namespace rows, retains raw diagnostics, and uses SQL exceptions instead of
argument-bearing psql quit commands. New runs use evidence_r2/; evidence/ is
historical and unchanged. All original test scope/permission limitations below
still apply. A fresh revision-2 SELECT-only preflight and separate runtime
authorization are required. Do not run the preparation generators to bypass pins.

Prepared 2026-10-30 (Asia/Calcutta). **PREPARATION ONLY: no SQL, users or HTTP
runtime probes have been executed.** TEST `ikmzxirldivefebgxzaa` only; production
`khweikfvsnervfuswhon` remains excluded. No Migration 02 or grant/policy changes.

## Decision and evidence boundary

**GO for separately authorized limited ACL/helper/FK/control testing**, after
provisioning two synthetic TEST Auth identities. **NO-GO for claiming comprehensive
runtime RLS tenant isolation or positive API CRUD with the current permissions.**
No authorization to execute is implied by this document.

Source of truth is the saved successful post-Migration01 verification, not a new
live connection. The hash-verified Apply and Verify receipts prove the committed
state and unchanged native/catalog snapshots. The earlier full schema export
supplies exact columns, FKs, indexes and policy expressions; Migration01 changed
only ACLs and its post-state confirms those objects unchanged. Future execution
rechecks the entire current metadata digest and aborts on drift before fixtures.

The older M01 snapshot does not serialize column definitions. Stage4 therefore
adds `assert_schema.sql` to compare exact live target column names, order, types,
nullability, defaults and identity flags with the captured 57-column specification
before fixtures, after rollback and in the fresh cleanup connection. This closes
that guard's coverage gap without changing database objects.

`verified_schema.json` records all five tables' 57 columns, 31 constraints, 15
indexes, five RLS settings, five policies and the actual post-M01 privilege matrix.
No Phase1 code or previous scripts/evidence are changed by Stage4 preparation.

| Table | Columns | Constraints | Indexes | RLS / policy |
|---|---:|---:|---:|---|
| security_events | 15 | 6 | 5 | enabled, not forced; authenticated SELECT |
| security_findings | 13 | 7 | 3 | enabled, not forced; authenticated SELECT |
| security_incidents | 14 | 9 | 4 | enabled, not forced; authenticated SELECT |
| incident_events | 5 | 4 | 1 | enabled, not forced; authenticated SELECT |
| security_risk_scores | 10 | 5 | 2 | enabled, not forced; authenticated SELECT |

Every SELECT policy uses exactly
`is_mesh_member(organization_id, ARRAY['security_team'::mesh_role])`, permissive,
for authenticated only; WITH CHECK is absent. There are no INSERT/UPDATE/DELETE
policies on these tables. Their ACLs contain only postgres's privileges.
anon/authenticated/authenticator/service_role have no effective table privileges
on these five tables after M01. No target column ACL entries exist.

The recovered is_mesh_member is SQL STABLE SECURITY DEFINER, postgres owned,
search_path empty, and schema-qualifies public.organization_members/auth.uid().
It requires matching organization, auth.uid(), active status and optional role
filter. Authenticated has EXECUTE; it grants no table access itself. Owner does
not implicitly satisfy the security_team filter. The Auth provisioning trigger
was deliberately omitted by the bootstrap; its unattached helper is preserved.
Native rls_auto_enable/ensure_rls remain untouched.

## What can and cannot be proved without changing grants

| Operation / identity | Actual current expectation | Interpretation |
|---|---|---|
| API SELECT, either company, anon/authenticated/service_role | 42501 / HTTP 401 or 403 | ACL denial before RLS; NOT tenant row filtering |
| API INSERT/UPDATE/DELETE, either company | 42501 | No legitimate API writer exists at this stage |
| postgres SELECT/INSERT/UPDATE/DELETE | succeeds on fixture | Owner/BYPASS control only, NOT an application boundary |
| authenticated helper A/B/security team | true only for active matching scope | Unit test of the actual policy predicate |
| suspended/outsider/missing subject/owner-only role | false for security_team scope | Helper negative cases; no new policy/grant |
| service_role | BYPASSRLS but no target ACLs | Bypass cannot supply missing table privileges |
| Authenticated SELECT returning own rows / excluding foreign rows | BLOCKED | Cannot exercise RLS row filtering without separately reviewed SELECT access |
| Positive tenant-scoped API writes | BLOCKED | No write grants/policies or restricted writer; M02 is outside scope |

Do not use the old Stage3 rls.sql: it temporarily grants SELECT. That violates
this stage's no-grant-change restriction. This package has NO GRANT/REVOKE/DDL,
policy edits, RLS disabling or role-membership changes. To unblock actual row
filtering later, separately review legitimate read-access requirements and their
minimal permissions in another proposal. Do not add them merely to get tests green.

## Identities and fixtures

Company A organization: `44444444-4444-4444-8444-000000000001`.
Company B organization: `44444444-4444-4444-8444-000000000002`.
Each receives a different synthetic Auth user and active security_team membership.
No existing real user is allowed. Profile/organization collisions cause failure.
All application fixtures stay within ONE transaction and are rolled back.

After separate explicit approval, use the **TEST Dashboard → Authentication →
Users → Add user / Create new user** (label may vary) for two synthetic accounts,
or a separately reviewed supported Auth administration client. Use distinct test
addresses/passwords under your control; do not send invitations to other people.
Do not paste passwords, API keys or JWTs into repository files/chat. Record only
the two UUIDs locally. Verify the Dashboard project ref before each action.
Do not INSERT/UPDATE/DELETE auth.users, auth.identities or auth.sessions directly.
Do not use production users, service-role keys or change Auth configuration to
bypass email confirmation. If this supported workflow is unavailable, stop.

Supabase documents the Users dashboard and supported management mechanisms:
[Managing user data](https://supabase.com/docs/guides/auth/managing-user-data),
[Auth users](https://supabase.com/docs/guides/auth/users).

Creating Auth accounts is persistent TEST setup; those accounts are NOT rolled
back by SQL fixtures. Cleanup is separately authorized deletion of exactly the
two created accounts through the TEST Dashboard after evidence review. Never
delete arbitrary users or the test project automatically. Existing access JWTs
can remain valid until expiry after user deletion; do not infer immediate token
revocation from account cleanup.

Runtime creates profiles, organizations/memberships, two assets and two complete
event → finding → incident → incident-event → risk chains. IDs and source
`vader-stage4` are reserved in fixture.sql. Incident numbers -44001/-44002 use
OVERRIDING SYSTEM VALUE under postgres, avoiding nontransactional nextval effects.
No sequence reset/setval or sequence ACL changes. A collision fails closed.
Each chain has same-organization references and valid inspected required fields,
types, statuses, numeric values and defaults; no guessed columns are used.

## Prepared test cases

1. **Preflight:** pinned sources, successful M01 receipt, fixed TEST route and TLS,
   correct operator/database/PG17, reviewed inventory/RLS and exact current catalog
   digest match. Auth UUIDs distinct/nonzero and profiles/fixture namespace absent.
2. **Positive owner controls, all five tables:** insert complete valid chains;
   SELECT exactly two fixture rows per table; UPDATE two; DELETE in FK-safe order
   and assert exact counts. Savepoint rollback restores chains. These control
   fixture validity, not tenant authorization.
3. **480 negative API statements:** three roles × two subjects × two spoofed
   organization claims × five tables × two target organizations × four CRUD
   operations. Each actual statement must fail 42501; no unconstrained read.
   No UUID/organization in the payload or claims enables API writes. Fail fast
   on any unexpected successful operation or unexpected error. A denied INSERT
   does not independently prove valid payload constraints, covered by controls.
4. **Membership helper:** A and B active scope, foreign scope, suspended member,
   outsider, missing auth identity, owner-only role; hostile organization/role
   user_metadata is ignored. No automatic owner/security privilege equivalence.
5. **Composite FKs:** five cross-tenant UPDATE and five INSERT attempts covering
   event→asset, finding→asset, finding→event, link→incident and link→event.
   Each must throw 23503 for its exact expected constraint. Owner exercises FKs
   independently of ACL/RLS. Same-tenant chains provide positive FK controls.
6. **Documented schema gaps:** owner can point A risk subject to B finding and A
   event.actor_user_id / incident.assigned_to to B's user. These successful probes
   are EXPECTED GAP confirmations, not a security PASS. Only existence in Auth is
   enforced for user references; organization membership is not. risk.subject_id
   has no FK. All three updates roll back immediately to a savepoint. No script
   attempts to fix them or executes M02. A future write surface must address them.
7. **Restoration:** rollback entire fixture savepoint; assert zero reserved rows
   in all fixture tables including profiles; compare full metadata snapshot with
   prefixture state; outer rollback with acknowledgement. Fresh read-only cleanup
   connection repeats zero-row and exact post-M01 catalog checks.

All statements are confined to the fixed disposable project and explicit fixture
IDs. Errors other than the narrowly caught 42501/23503 cases terminate psql and
roll back on disconnect. Temporary role/JWT settings are transaction-local.
Short exclusive table locks keep fixture tests coherent; busy project/timeout is
FAIL, not permission to terminate sessions or weaken checks.

## Identity spoofing and real JWT boundary

An admin SQL session can SET ROLE and set request.jwt.claim.sub; such tests are
trusted impersonation, not authentication. The helper trusts the identity supplied
by the authenticated gateway. It cannot cryptographically verify GUC values or
stop a privileged direct-SQL caller changing them. No claim of preventing this
admin behavior is made. Native postgres/service-role bypass privileges remain.

Optional `jwt_boundary.py` tests the actual gateway with two fresh TEST access
JWTs obtained through a supported TEST sign-in flow. It does not sign in, create
users or alter accounts itself. Prompted keys/tokens stay in memory. Only TEST
publishable keys are accepted, never secret/service-role keys. Local issuer/sub/
role hints are checked before network activity, then /auth/v1/user authenticates
each token and expected identity. Modified sub/role/organization claims retaining
the original signature and an unsigned token must be rejected. Client X-User-Id /
X-Organization-Id headers must not replace A's authenticated identity.

GET-only Data API checks all five tables for A/B filters under anon/A/B: all must
remain denied. This proves current API ACL denial, NOT successful RLS filtering
or a future RPC's payload validation. Signed JWT verification is tested through
Auth; no backend/RPC exists here to test tenant claims in a writer. No secret key
is requested merely to demonstrate BYPASSRLS. SQL role tests distinguish its
attribute from its absent ACLs. HTTPS certificate verification is mandatory,
redirects are disabled and the endpoint is hardcoded to TEST.

Reference: [Supabase RLS](https://supabase.com/docs/guides/database/postgres/row-level-security),
[Securing data](https://supabase.com/docs/guides/database/secure-data).
Our captured ACLs, rather than generic platform default grants, determine expected
permissions in this project. Do not use user-editable metadata for authorization.

## Files and future execution steps

`Invoke-Stage4.ps1` accepts only Validate, Runtime or CleanupCheck, with fixed TLS
session-pooler route/user and psql18.6. It pins the full SQL/include closure,
post-M01 evidence and scripts; reserves a receipt once before execution; clears
inherited libpq settings; never retries or overwrites evidence. It has no fixture
commit, grant-change, M02 or production action. Runtime and cleanup are separate
password prompts in your own terminal. No background prompt window is launched.

Local checks already run (no authorization for runtime implied):

```powershell
$stage4Runner = 'C:\Users\APOORV\OneDrive\Desktop\MESH\meshcode\Mesh\supabase\testing\ikmzxirldivefebgxzaa\stage4\Invoke-Stage4.ps1'
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File $stage4Runner -Action Validate
```

Only after explicit approval of TEST user setup and the limited SQL cases:

```powershell
# Assign the two new nonsecret Auth UUIDs to these variables in your own terminal.
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File $stage4Runner -Action Runtime -ApproveStage4 -UserA $stage4UserA -UserB $stage4UserB
# Run only after Runtime PASS; fresh READ ONLY verification:
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File $stage4Runner -Action CleanupCheck -ApproveStage4 -UserA $stage4UserA -UserB $stage4UserB
```

Optional HTTP checks need separate explicit authorization and fresh JWTs:

```powershell
python 'C:\Users\APOORV\OneDrive\Desktop\MESH\meshcode\Mesh\supabase\testing\ikmzxirldivefebgxzaa\stage4\jwt_boundary.py' --approve-stage4 ikmzxirldivefebgxzaa
```

No runtime command has been executed. Do not run build_stage4.py to bypass hash
failures after review. Local generator only creates preparation artifacts/pins.
Receipt markers remain after failures; never delete them to force a retry.

## PASS/FAIL, evidence and cleanup

| Area | PASS | FAIL/BLOCKED |
|---|---|---|
| Integrity/target | All pins, successful M01 evidence and server metadata match | Any drift or wrong identity: NO-GO before fixture |
| Fixture/admin controls | Valid chain and exact owner CRUD counts | FK/type/collision/permission error: fail and rollback |
| API boundary | All 480 CRUD attempts return expected 42501 | Any access or other unexpected error: fail |
| Helpers | Correct active company/role scope; spoofed metadata ignored | False authorization: fail |
| FKs | 10 exact 23503 errors, positive same-tenant chain valid | Cross-tenant association succeeds/wrong constraint: fail |
| Known missing constraints | Recorded as existing security gaps | Never treat owner acceptance as isolation success |
| RLS row filtering/API positive CRUD | BLOCKED by current ACL/policy design | Cannot mark full isolation PASS |
| Real JWT | Signed users verified; mutations rejected; headers ignored | Unauthenticated/forged identity accepted: fail; unavailable JWT/endpoint: blocked |
| Cleanup | Zero reserved rows and identical metadata in same/fresh connections | Residual rows/ACL drift: fail; no automatic cleanup writes |

Evidence is sanitized JSON/query output under stage4/evidence: runtime.txt,
runtime.receipt.json, cleanup_check.txt, cleanup_check.receipt.json and optional
jwt_boundary.json. SQL errors/SQLSTATE should be reported without credentials.
No Auth records, emails, passwords, raw JWTs or response bodies are retained.

If psql errors, stop; the transaction rolls back on disconnect. No COMMIT exists
in any SQL execution path. If acknowledgement is lost, do not retry; request a
separately approved read-only outcome check. CleanupCheck currently requires a
successful Runtime receipt, so a failed-run investigation requires new approval
and review rather than bypassing that guard. No bulk DELETE/TRUNCATE/reset/drop
procedure exists. Only approved TEST Dashboard deletion of the two created Auth
accounts remains after SQL rollback and evidence review.

## Validation and remaining blockers

Static checks passed for pinned source/post-M01 receipts, exact inspected fields
and FK names, include resolution, no COMMIT/DDL/grant/policy/Auth writes, explicit
identity override, ten FK cases, 480 ACL probes, Python AST and PowerShell parsing.
Default launcher Validate succeeded without connecting. PostgreSQL compilation,
PLpgSQL behavior, real API status codes and all runtime assertions remain untested.

Before limited execution: explicit authorization, two NEW synthetic TEST Auth
users, matching UUIDs, interactive TEST database password and unchanged runtime
catalog. Optional HTTP additionally needs TEST publishable key/fresh user JWTs.
No original or new service-role secret is needed. Full Stage4 security sign-off
remains NO-GO because positive API operations/RLS row filtering cannot be tested
under unchanged grants, and risk/user tenant-reference constraints remain absent.
