# VADER Stage 4B-read — local TEST harness

Preparation only. **No SQL, grants, fixtures or database connections executed.**
TEST: `ikmzxirldivefebgxzaa`. Production `khweikfvsnervfuswhon` is prohibited.
GO for review and separately authorized TEST-only rollback testing; NOT a claim
that the new SQL has compiled or that tenant-filtered reads have passed live.

## Verified existing contract

Inputs are the exact inspected schema and the hash-verified Stage4 R2 LIMITED
PASS runtime/cleanup evidence. The five postgres-owned public tables have 57
columns, 31 constraints, 15 indexes and five SELECT-only RLS policies. RLS is
enabled, not forced. All five policies target authenticated with the exact
predicate `is_mesh_member(organization_id, ARRAY['security_team'::mesh_role])`.
No API SELECT or writes exist on these tables after Migration01; R2 proved
current ACL denials, helper and FK behavior, not RLS-filtered SELECT.

is_mesh_member is SQL STABLE SECURITY DEFINER, postgres owned, empty search_path,
and schema-qualifies public.organization_members/auth.uid(). It verifies active
membership, actual user identity and requested role. Its authenticated EXECUTE
and public schema USAGE already exist and remain unchanged. Existing metadata
hashes guard its body, ownership, settings and ACL; it is not replaced here.

App roles are owner, hr, senior_developer, junior_developer and security_team.
They are membership enum values, not database LOGIN roles. Authenticated remains
the actual SQL/API role; only active security_team membership satisfies reads.
No owner override or additional HR/developer visibility is invented.

## Exact permission proposal

`grant_select_proposal.sql` contains only an execution gate and this grant:

```sql
GRANT SELECT ON TABLE public.security_events,public.security_findings,
 public.security_incidents,public.incident_events,public.security_risk_scores
TO authenticated;
```

No grant option, schema/sequence grant, foundation-table access, role membership,
INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER or MAINTAIN is added. Anonymous,
service_role and authenticator permissions remain unchanged. All policies remain
unchanged. Treat the proposal as a transaction fragment; do not execute it alone.
The runtime grants SELECT only inside a transaction that always rolls back.
This is not a committed read-access migration or authorization for deployment.

`assert_delta.sql` requires EXACTLY five false→true effective cells: authenticated
SELECT for those five tables. The remaining 195 effective cells must match the
original snapshot. Each target ACL must differ by exactly one non-grantable
`authenticated=r/postgres` entry; grantor, owner, grantee and privilege are checked.
ACL-item ordering alone is irrelevant, but added/removed/changed items are not
ignored. No column ACL change is allowed. Every native metadata category must
remain identical, including policies, helpers, roles, other table/schema ACLs,
sequences, defaults, triggers, constraints and indexes. This catches inherited
anon/service-role exposure as well as direct grants.

No new baseline is generated. The original baseline MD5 remains
`90a71db3b16ed177b3455f61a59343b2`. R2's narrow system-temporary-namespace projection
is reused unchanged. Granted/tested metadata intentionally has a different hash;
that difference is accepted ONLY after the exact delta assertion passes twice.
Both preflight and restored/cleanup states must match the ORIGINAL baseline.

## Test matrix — all five tables

| Case | Identity / membership | Expected visible fixture rows per table |
|---|---|---:|
| active_security_a | A, active security_team in A | 1 A; zero B |
| active_security_b | B, active security_team in B | 1 B; zero A |
| owner | A, active owner in A | 0 |
| hr | A, active hr in A | 0 |
| senior_developer | A, active senior_developer in A | 0 |
| junior_developer | A, active junior_developer in A | 0 |
| suspended | A, suspended security_team | 0 |
| offboarded | A, offboarded security_team | 0 |
| pending | A, pending security_team | 0 |
| outsider | Reserved UUID with no Auth identity/membership | 0 |
| missing_identity | Empty subject and no claims | 0 |
| spoof_foreign_organization | A active security_team, claims/user_metadata say B | 1 A; zero B |
| metadata_role_escalation | A active junior_developer, user_metadata says security_team | 0 |
| invalid_identity | Malformed UUID subject | 22P02, no successful read |

For each of 13 valid/missing/outsider cases, each table is tested with nine read
assertions: unfiltered count, explicit own filter, explicit foreign filter,
grouped counts, ordered pagination, non-own-row count, DISTINCT organization
count, same-organization join and cross-organization join. Joins use only the
five granted tables, not foundation tables. Counts/grouping/pagination must not
leak hidden tenant rows. No real application data is printed or retained.

The malformed-identity case requires the exact invalid_text_representation state
22P02 on all five tables. Total: **590 authenticated read assertions / 14 cases**.
Additionally, **15 real SELECT denial probes** cover anon, service_role and
authenticator across all five tables. service_role BYPASSRLS does not substitute
for missing table privileges. No write statement is issued as authenticated.
Forbidden write/dangerous permissions are verified through the exact 200-cell
effective-privilege matrix, not by authorizing a write operation.

Membership role/status changes are performed by the trusted TEST admin ONLY on
the synthetic rows inside the fixture transaction. Policies always read trusted
membership records; user_metadata never grants authorization. SQL-local identity
claims are trusted impersonation for policy unit tests, not JWT authentication.

## Fixtures, guards and cleanup

The same two existing synthetic TEST Auth UUIDs are required, in their reviewed
mapping; the launcher rejects any others:

- A: `72a7251d-b69b-4149-8a7f-a082e4b920e9`.
- B: `8c9907c9-4acf-480b-aaee-dcd08f3cbc6a`.

New Company A/B organization IDs are respectively
`55555555-5555-4555-8555-000000000001` and
`55555555-5555-4555-8555-000000000002`. Asset/event/finding/incident/risk child IDs
use that same new prefix; fixture.sql is mechanically derived from the inspected,
R2-tested fixture with only its namespace/labels/numbers changed. Incident
numbers -54001/-54002 use OVERRIDING SYSTEM VALUE; no sequence advance/reset.
No Auth user or managed record is created, updated or deleted.

assert_clean.sql checks supplied profiles/memberships, both reserved organizations,
all reserved child IDs across ALL organizations, incident-link references and
negative numbers -54001/-54002/-54999. Both Auth identities must exist and the
reserved outsider UUID must not be an existing Auth user. Any collision is fatal.
It is stricter than merely checking that the two organizations are absent.

Runtime has one BEGIN and no COMMIT or procedure CALL. It takes short exclusive
locks on the nine fixture tables, verifies metadata/columns/collisions, saves a
savepoint, then creates fixtures and applies the temporary SELECT grant. Admin
fixture INSERTs/membership UPDATEs are test setup, not an authenticated write path.
After reads, it reasserts the exact delta, rolls back the fixture savepoint, checks
zero residue and exact original metadata/column restoration, then performs outer
ROLLBACK. Success requires STAGE4B_READ_ROLLBACK_ACKNOWLEDGED. Any unexpected SQL
error causes fail-fast disconnect rollback; no retry or cleanup writes are automatic.

A fresh CleanupCheck connection is READ ONLY and repeats original-baseline,
column and zero-residue checks. Synthetic Auth users remain unchanged afterward.
If a run fails, retain its receipt/output and stop; successful-runtime dependency
prevents blindly running CleanupCheck after failure. A failed/unknown outcome
needs a separately reviewed read-only investigation, never deleting markers or
regranting permissions to make tests pass.

## Launcher, pins and evidence

New directory only: stage4b_read/. R2 files, pins, old failed evidence and LIMITED
PASS evidence are untouched. New pins include all unchanged R2 dependencies, its
four completion files and all new executable artifacts. Old historical launchers
are not invoked or repinned. No build or migration CLI command is executed.

Invoke-Stage4BRead.ps1 exposes only local Validate, Runtime and CleanupCheck.
No arbitrary SQL/host/project input. It fixes the reviewed TEST session pooler,
port5432/postgres database, `postgres.ikmzxirldivefebgxzaa` username and verify-full
TLS with pinned CA. It clears inherited libpq routing/credentials, uses psql -X -W
and ON_ERROR_STOP, prints original SQLSTATE/errors, and reserves each phase once.
Password entry remains interactive in the operator's own terminal; no password,
key, JWT, service credential or connection string is written to repository files.

Evidence is NEW stage4b_read/evidence/runtime.txt and runtime.receipt.json, followed
by cleanup_check.txt and cleanup_check.receipt.json. Logs contain preflight,
granted, tested and restored metadata, two exact-delta records, detailed case
results, restricted-role read results, collision checks, final result and rollback
acknowledgement. The parser distinguishes intentional granted-state hash changes
from baseline failures and rejects missing/duplicate evidence. Receipt hashes
support local consistency; they are not an external tamper-proof audit system.

## Future commands — separate execution authorization required

Local Validate performs no SQL/network operation:

```powershell
$runner = 'C:\Users\APOORV\OneDrive\Desktop\MESH\meshcode\Mesh\supabase\testing\ikmzxirldivefebgxzaa\stage4b_read\Invoke-Stage4BRead.ps1'
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File $runner -Action Validate
```

Do NOT run these runtime commands under planning authorization:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File $runner -Action Runtime -ApproveStage4BRead -UserA '72a7251d-b69b-4149-8a7f-a082e4b920e9' -UserB '8c9907c9-4acf-480b-aaee-dcd08f3cbc6a'
# Only after Runtime PASS, if the fresh read-only check is also authorized:
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File $runner -Action CleanupCheck -ApproveStage4BRead -UserA '72a7251d-b69b-4149-8a7f-a082e4b920e9' -UserB '8c9907c9-4acf-480b-aaee-dcd08f3cbc6a'
```

## SQL-role tests versus real JWT/API tests

This harness has no HTTP/JWT runtime code and does not claim cryptographic
authentication or PostgREST end-to-end coverage. SET LOCAL ROLE/request claims by
postgres simulate a gateway; privileged SQL callers can change those claims.
The invalid-identity check is UUID-input rejection, not JWT signature rejection.

Real JWT/API positive-read tests need a separate design/approval. Other API
connections cannot see uncommitted fixtures or this uncommitted SELECT grant.
They therefore require separately approved, temporarily committed TEST fixtures
and a committed scoped permission change, followed by explicit compensating
cleanup/ACL restoration. Do not reuse the old JWT test expecting denied reads
and call it positive RLS proof. No committed fixture or grant is prepared here.

## Offline validation and remaining risks

PASS: new/unchanged dependency hashes and R2 receipts; recursive include scope;
single exact SELECT grant; field/case coverage; transaction ordering; synthetic
permission-delta mutation rejection models; Python AST; PowerShell parsing;
eight synthetic evidence/parser failure paths; local Validate mode. These tests
do not invoke SQL, the runtime launcher or a database. No SQL parser/compiler
is installed; PostgreSQL/PLpgSQL compilation and actual grant/ACL rendering,
identity rejection, RLS visibility and rollback remain live-test assumptions.

All SELECT permissions are table-level, so this would expose all columns of
authorized tenant rows, including details/evidence, for as long as the grant is
active. Before any production proposal, review sensitive payload/column scope.
Global default-grant risks and the existing risk-subject/user-reference integrity
gaps remain unchanged. This read-only authorization harness does not fix or expose
an authenticated writer. It does not authorize M02, production, deployments,
committed grants/fixtures, users, permission changes outside its rollback scope,
or new Owner/HR/developer access.

**Recommendation: GO for a separately authorized, one-attempt TEST rollback-only
SQL-role read validation. NOT RUN / no database claim yet. NO-GO for real API
positive-read sign-off, authenticated writes, production or committed access changes.**
