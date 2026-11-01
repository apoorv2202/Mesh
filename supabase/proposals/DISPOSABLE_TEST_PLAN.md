# VADER Phase 2 disposable Supabase runtime test plan

Status: preparation only, 2026-10-29. **Execution requires user approval.**
No resources, SQL sessions, roles, migrations or deployments were created/run.
Production project `khweikfvsnervfuswhon` is excluded from every execution step.
The two proposals remain outside migrations/ and production remains NO-GO.

Current bootstrap revision: use `supabase/testing/ikmzxirldivefebgxzaa/README.md`
and its fidelity manifest/review. Actual TEST preflight and psql 18.6 are now
available; older missing-client/source setup notes below are historical. The
revised bootstrap REUSES native rls_auto_enable/ensure_rls without mutation and
deliberately does NOT attach the Auth-to-profile trigger. Provisioning tests must
use explicit synthetic profile seeding as described below; automatic Auth-user
profile provisioning is outside this fixture's coverage. No test was run here.

## 1. Prerequisites, Free plan and isolation

Use one separately named project, `mesh-vader-disposable`, in an organization
whose dashboard explicitly shows Free. Do not create it inside a paid organization
assuming the second project will be free. Supabase currently lists two active
Free projects and 500 MB database size per project; inactivity can pause a Free
project after one week. Check the account's actual available project slot first.
If none is available, stop: do not pause/delete MESH, upgrade, create paid branches,
or buy an add-on without separate approval.

Use a tiny synthetic fixture and at most three concurrent client connections.
No PITR, paid branching, dedicated pooler, Edge Function deployment, custom domain
or dedicated IPv4 is needed. Direct connections can require IPv6; the shared
session pooler on port 5432 supports IPv4. Custom-role pooler usernames are
`ROLE.TEST_PROJECT_REF`. Confirm actual session_user and transaction behavior,
not merely whether authentication succeeds. Do not use HTTP RPC or transaction
pooling for the initial pinned-session test.

Sources checked for this plan:
[pricing](https://supabase.com/pricing),
[connections/custom pooler users](https://supabase.com/docs/guides/database/connecting-to-postgres),
[connection pooling](https://supabase.com/docs/guides/database/connecting-to-postgres/pooling-and-limits),
[Free-project pausing](https://supabase.com/docs/guides/platform/free-project-pausing).
Limits may change; confirm them in the dashboard before creating anything.

Current workstation limitation: psql is not on PATH. Before execution, approve
installation/use of Windows PostgreSQL client tools (psql; optionally pg_dump).
No server, WSL or Docker is required. A trusted Windows GUI client with persistent
sessions can substitute, but the command-line instructions below use psql. SQL
Editor alone cannot prove authentication as two real database LOGIN identities.

Do not relink this repository: its existing Supabase link points at MESH. Do not
use any --linked command, db push/reset, migration repair or deploy command.
Use explicit TEST host/user parameters and interactive password prompts. Never
put passwords, tokens, service keys or full connection strings in files/logs.

## 2. Reproduce schema faithfully: source and minimum dependency closure

**Blocking input:** the consolidated verification result/helper definitions and
the original three reviewed SQL scripts are not saved here. The existing
mesh_inspection.json has WITHHELD function bodies; schema_snapshot.sql is empty.
High-level confirmation that is_mesh_member checks active membership/auth.uid
does not provide its exact body, search_path, grants or defaults. Do not create a
stub returning true or invent a replacement schema to get green tests.

Choose one source before executing setup:

1. Prefer the three original manually applied MESH SQL scripts plus the sanitized
   consolidated export. Review scripts offline and remove any application seeds,
   credentials, network calls or external integrations from a TEST-only copy.
   Compare the resulting catalog to the inspected state to account for later drift.
2. Alternatively obtain an approved, schema-only public export supplied by the
   user/DB administrator, with exact custom helper definitions, ACLs, identity
   sequence configuration and custom event-trigger registration. This plan does
   not authorize connecting to production to produce that export.
3. If neither exists, stop before bootstrap. Future reconstruction is permissible
   only from the exact inspected definitions, not table names; it needs separate
   review for identity options, dependency ordering and omitted helper bodies.

The simplest faithful small test is all 18 application table DEFINITIONS with
zero production rows. Eighteen empty tables cost little and avoid hidden helper
dependencies. The strict minimum target closure is ten tables:

| Order | Objects | Why |
| --- | --- | --- |
| Native Supabase | Existing auth schema/users, roles, auth.uid(), managed extensions | Supplied by the NEW project; never restore production-managed schemas/users |
| Types | public.mesh_role, public.mesh_member_status | Exact labels/order from inspection |
| Foundation | organizations, profiles, organization_members | Tenant FKs and active-membership helper |
| Infrastructure | cloud_integrations, security_assets | Exact event/finding asset FK dependency, even with NULL fixture assets |
| Persistence | security_events, security_findings, security_incidents, incident_events, security_risk_scores | Five tables; exact columns/checks/FKs/indexes/defaults |
| Routines/security | Three public helpers, relevant row/event triggers, policies, grants, default ACLs | Reproduce actual authorization and DDL side effects |
| Sequence | security_incidents_incident_number_seq | Preserve GENERATED ALWAYS identity and configuration; don't create a duplicate sequence |

If a real helper references audit_logs, invitations or another omitted table,
expand the closure, normally to all 18 definitions. Do not delete helper logic.
Compare uuid-ossp and pgcrypto locations/signatures (extensions) and plpgsql.
Do not install/copy vault data or configure Azure/AWS services.

Retain the new project's Supabase-managed role relationships. Compare captured
membership edges/options against the actual production verification, but do not
blindly replay a global roles dump, ALTER managed roles or add postgres membership
to test callers. Reproduce the four dangerous grants ONLY on these disposable
application tables so migration 01 is tested against its real starting condition.
Record differences in managed roles/default ACLs as confidence limitations.

After source review, stage the exact schema-only TEST bootstrap as
`bootstrap_reviewed.sql` in the temporary workspace below. This prerequisite file
is intentionally NOT generated by this planning task. It must contain only the
reviewed application schema/security setup, not project credentials or user data.

## 3. Exact execution setup after approval

1. In Supabase Dashboard, create `mesh-vader-disposable` on Free using a new secret
   password; record only its non-secret project reference. Do not run any wizard
   that migrates production data. Verify PostgreSQL 17 (minor differences recorded).
2. Obtain the TEST session-pooler hostname and TLS CA certificate from its Connect
   panel. Keep passwords in a password manager; no URI is copied into the repo.
3. Open a NEW PowerShell terminal at the repository root. These are future commands,
   not commands executed by this preparation task:

```powershell
$vaderTestRef = Read-Host 'Disposable project reference (NOT MESH)'
if ($vaderTestRef -eq 'khweikfvsnervfuswhon' -or $vaderTestRef -notmatch '^[a-z0-9]{20}$') { throw 'Invalid TEST reference' }
$env:PGHOST = Read-Host 'TEST shared session-pooler hostname only'
if ($env:PGHOST -notmatch '^[-a-z0-9]+\.pooler\.supabase\.com$') { throw 'Use the reviewed shared session endpoint' }
$env:PGPORT = '5432'
$env:PGDATABASE = 'postgres'
$env:PGSSLMODE = 'verify-full'
$env:PGSSLROOTCERT = Read-Host 'Absolute path to downloaded TEST TLS root certificate'
if (!(Test-Path -LiteralPath $env:PGSSLROOTCERT)) { throw 'TLS certificate missing' }
$env:PGAPPNAME = 'mesh-vader-disposable-tests'
$env:PGCONNECT_TIMEOUT = '10'
Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
Remove-Item Env:PGSERVICE -ErrorAction SilentlyContinue
Remove-Item Env:PGSERVICEFILE -ErrorAction SilentlyContinue
$env:PGOPTIONS = '-c statement_timeout=15000 -c lock_timeout=3000 -c idle_in_transaction_session_timeout=60000'
$vaderTestRoot = Join-Path ([IO.Path]::GetTempPath()) ('mesh-vader-test-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $vaderTestRoot | Out-Null
$repoRoot = (Get-Location).Path

function Invoke-VaderTestSql {
    param(
      [ValidateSet('postgres','vader_tenant_a_test','vader_tenant_b_test','vader_unmapped_test')][string]$Role = 'postgres',
      [string]$Sql,
      [string]$File
    )
    if ($vaderTestRef -eq 'khweikfvsnervfuswhon' -or $vaderTestRef -notmatch '^[a-z0-9]{20}$') { throw 'TEST target refused' }
    if ($env:PGHOST -notmatch '^[-a-z0-9]+\.pooler\.supabase\.com$' -or $env:PGPORT -ne '5432' -or $env:PGDATABASE -ne 'postgres') { throw 'Endpoint drift' }
    if ($env:PGSSLMODE -ne 'verify-full') { throw 'TLS verification required' }
    if ([bool]$Sql -eq [bool]$File) { throw 'Provide exactly one SQL command or file' }
    $env:PGUSER = "$Role.$vaderTestRef"
    $vaderPsqlArgs = @('-X','-W','-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose')
    if ($File) {
      $resolved = (Resolve-Path -LiteralPath $File).Path
      if (!$resolved.StartsWith($vaderTestRoot + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Only staged TEST files allowed' }
      $vaderPsqlArgs += @('-f',$resolved)
    } else { $vaderPsqlArgs += @('-c',$Sql) }
    & psql @vaderPsqlArgs
    Write-Host "psql exit code: $LASTEXITCODE"
}

Invoke-VaderTestSql -Sql 'SELECT current_database(),current_user,session_user,version();'
```

Expected: test endpoint authenticates as postgres, PostgreSQL 17. The SQL output
does NOT prove project ref; the explicit pooler username/host and dashboard do.
If custom-role pooler authentication fails later, record failure; do not buy
IPv4 or switch to production credentials. A separately approved IPv6 direct
connection can be evaluated instead, with a TEST-ref-specific host allowlist.

Stage only local copies of the proposals/checks and reviewed bootstrap. Keep
the proposal bytes unmodified; gate flags are supplied by a test wrapper:

```powershell
Copy-Item -LiteralPath (Join-Path $repoRoot 'supabase/proposals/01_vader_security_hardening.sql') -Destination (Join-Path $vaderTestRoot '01.sql')
Copy-Item -LiteralPath (Join-Path $repoRoot 'supabase/proposals/02_vader_transactional_writer.sql') -Destination (Join-Path $vaderTestRoot '02.sql')
Copy-Item -LiteralPath (Join-Path $repoRoot 'supabase/inspection/consolidated_vader_verification.sql') -Destination (Join-Path $vaderTestRoot 'verify.sql')
# Place the reviewed schema source at $vaderTestRoot/bootstrap_reviewed.sql first.
Invoke-VaderTestSql -File (Join-Path $vaderTestRoot 'bootstrap_reviewed.sql')
Invoke-VaderTestSql -File (Join-Path $vaderTestRoot 'verify.sql')
```

Stop if source is missing, any bootstrap error occurs, or catalog parity fails.
Expected before 01: exact five-table 57/31/15 structure and original four dangerous
effective rights on all three API roles; zero column ACLs; correct RLS/helper and
sequence definitions. Use the JSON output rather than just row counts. Export
before/after JSON without raw helper secrets, plus local proposal hashes using
`Get-FileHash -Algorithm SHA256` on the staged 01.sql and 02.sql.

## 4. Minimum synthetic data

For migration 01 ACL/rollback tests no table rows are necessary. For writer tests,
use two organizations, the same actor string across tenants, four events per
tenant and one complete chain per tenant. Each successful bundle should produce
4 events, 4 findings, 1 incident, 4 incident links and 5 risk rows (four finding
scores and one incident score), plus 15 receipts (one bundle + 14 entity receipts).
No actual cloud integrations/assets are required; their definitions remain for FKs.

TEST-only organization seed (verified existing columns):

```sql
INSERT INTO public.organizations(id,name,status) VALUES
 ('11111111-1111-4111-8111-111111111111','VADER disposable A','active'),
 ('22222222-2222-4222-8222-222222222222','VADER disposable B','active');
```

To test existing membership helpers, create four synthetic Auth users using the
TEST project's Dashboard Add User flow, without sending invitation emails:
security-a@vader.test, security-b@vader.test, suspended-a@vader.test and
outsider@vader.test. Do not INSERT directly into auth.users. The native-preserving
bootstrap omits the application Auth provisioning trigger intentionally. As the
TEST admin, explicitly seed public.profiles for the newly created TEST Auth UUIDs,
then organization_members: active security_team A/B, suspended security_team A,
outsider with no membership. Do not attach an Auth trigger as a workaround.
psql `\prompt` can collect the non-secret TEST UUIDs:

```sql
\prompt 'security-a TEST profile UUID: ' sec_a
\prompt 'security-b TEST profile UUID: ' sec_b
\prompt 'suspended-a TEST profile UUID: ' suspended_a
\prompt 'outsider TEST Auth user UUID: ' outsider
INSERT INTO public.profiles(id,full_name) VALUES
 (:'sec_a'::uuid,'Synthetic security A'),
 (:'sec_b'::uuid,'Synthetic security B'),
 (:'suspended_a'::uuid,'Synthetic suspended A'),
 (:'outsider'::uuid,'Synthetic outsider');
INSERT INTO public.organization_members(organization_id,user_id,role,status) VALUES
 ('11111111-1111-4111-8111-111111111111',:'sec_a'::uuid,'security_team','active'),
 ('22222222-2222-4222-8222-222222222222',:'sec_b'::uuid,'security_team','active'),
 ('11111111-1111-4111-8111-111111111111',:'suspended_a'::uuid,'security_team','suspended');
```

Save TEST snippets to the temporary workspace and use Invoke-VaderTestSql -File.
Fixture IDs and .test emails are synthetic; Auth passwords are never exported.

## 5. Migration 01: isolated tests before committed application

For each test, capture relevant target ACLs and role-membership edges before/after
from verify.sql. Exclude captured_at when comparing. Expected failures use psql
ON_ERROR_STOP, a nonzero exit code and a closed connection; transactional work
must not remain. Never catch failures and then blindly continue the next stage.

| Test | Exact action | Expected result |
| --- | --- | --- |
| Closed gate | Run staged 01.sql unchanged | Review gate exception; no ACL change |
| Column-grant drift | TEST-only `GRANT UPDATE(source) ON public.security_events TO authenticated;`, run approved wrapper below | Preflight rejects column ACL; revoke just that test column grant afterwards; no other ACL change |
| Inherited dangerous path | Add synthetic parent below; run approved wrapper | Postflight rejects residual TRUNCATE and rolls back its other revocations |
| Dry-run rollback | Run rollback-copy below | Revocations succeed inside transaction; final ROLLBACK restores original rights |
| Success | Remove only synthetic test alterations; run approved wrapper | All four dangerous rights false for all API roles, frontend DML false, original memberships/RLS unchanged |

Create the **TEST-only** approved wrapper locally after approval:

```powershell
$wrapper01 = "SET mesh_review.security_approved = 'on';`n\ir 01.sql`n"
Set-Content -LiteralPath (Join-Path $vaderTestRoot 'run01.sql') -Value $wrapper01 -Encoding UTF8
Invoke-VaderTestSql -File (Join-Path $vaderTestRoot '01.sql') # expected failure first
```

Inherited-path setup/cleanup must touch only a new synthetic role in TEST:

```sql
-- Setup; execute once, before running run01.sql in another admin session.
CREATE ROLE vader_test_parent NOLOGIN;
GRANT TRUNCATE ON public.security_events TO vader_test_parent;
GRANT vader_test_parent TO anon WITH INHERIT TRUE, SET FALSE;
-- Expected test run01.sql failure; capture ACLs before cleanup.
-- Cleanup only the synthetic relationship/grant; never managed memberships:
REVOKE vader_test_parent FROM anon;
REVOKE TRUNCATE ON public.security_events FROM vader_test_parent;
DROP ROLE vader_test_parent;
```

For the rollback test, derive a local test-only variant; proposals contain their
own BEGIN/COMMIT, so wrapping them in another BEGIN is NOT a rollback test:

```powershell
$sql01 = Get-Content -LiteralPath (Join-Path $vaderTestRoot '01.sql') -Raw
if ([regex]::Matches($sql01,'(?m)^COMMIT;\s*$').Count -ne 1) { throw 'Unexpected transaction layout' }
$rollback01 = [regex]::Replace($sql01,'(?m)^COMMIT;\s*$','ROLLBACK;')
Set-Content -LiteralPath (Join-Path $vaderTestRoot 'rollback01.sql') -Encoding UTF8 -Value ("SET mesh_review.security_approved = 'on';`n" + $rollback01)
Invoke-VaderTestSql -File (Join-Path $vaderTestRoot 'rollback01.sql')
Invoke-VaderTestSql -File (Join-Path $vaderTestRoot 'verify.sql')
# Only after all expected failure/rollback checks pass:
Invoke-VaderTestSql -File (Join-Path $vaderTestRoot 'run01.sql')
Invoke-VaderTestSql -File (Join-Path $vaderTestRoot 'verify.sql')
```

Expected successful committed outcome: no remaining four dangerous rights and no
new grants or changed Supabase-managed role edges. If residual inherited rights
make 01 fail, STOP; the correct response is a focused proposal review, not removing
managed role memberships. Default ACL behavior for future tables is reported
separately; 01 deliberately does not change creator-wide defaults.

For a direct SQL privilege demonstration, before AND after 01 use only the
disposable empty risk table (inspection shows no inbound FK to this table):

```sql
BEGIN;
SET LOCAL ROLE anon;
TRUNCATE TABLE public.security_risk_scores;
ROLLBACK;
```

Before 01: succeeds despite RLS, then rolls back. After 01: expected 42501. Run
through a short-lived TEST admin psql connection so an expected error closes and
rolls back the session. This is a privilege unit test using SET ROLE, not a login
authentication test. If target schema now has inbound references, report the
limitation; do not add CASCADE or additional tables to make TRUNCATE succeed.

## 6. Migration 02: compilation, setup rollback and provisioning

Before committed 02, repeat closed-gate and final-COMMIT-to-ROLLBACK copy tests
using mesh_review.writer_approved. Check both proposed roles/schemas absent before
and after the failed/rollback runs; existing tables must still have 57 columns
total, 31 constraints and 15 indexes. A failed CREATE ROLE/ALTER OWNER is a result,
not permission to grant a caller postgres/admin membership.

```powershell
Invoke-VaderTestSql -File (Join-Path $vaderTestRoot '02.sql') # expected closed gate
$sql02 = Get-Content -LiteralPath (Join-Path $vaderTestRoot '02.sql') -Raw
if ([regex]::Matches($sql02,'(?m)^COMMIT;\s*$').Count -ne 1) { throw 'Unexpected transaction layout' }
$rollback02 = [regex]::Replace($sql02,'(?m)^COMMIT;\s*$','ROLLBACK;')
Set-Content -LiteralPath (Join-Path $vaderTestRoot 'rollback02.sql') -Encoding UTF8 -Value ("SET mesh_review.writer_approved = 'on';`n" + $rollback02)
Invoke-VaderTestSql -File (Join-Path $vaderTestRoot 'rollback02.sql')
Invoke-VaderTestSql -File (Join-Path $vaderTestRoot 'verify.sql')
```

Create/test a synthetic orphan risk row **inside an admin transaction**, attempt
the FK ALTER fragment, then ROLLBACK. It must fail, preserving existing schema;
do not permanently insert invalid rows. This tests existing-data rejection without
requiring a failed full-role setup. Document a partial test if platform restrictions
prevent reproducing the exact migration transaction. Never use NOT VALID to hide it.

Successful install command after failure/rollback tests:

```powershell
Set-Content -LiteralPath (Join-Path $vaderTestRoot 'run02.sql') -Encoding UTF8 -Value "SET mesh_review.writer_approved = 'on';`n\ir 02.sql`n"
Invoke-VaderTestSql -File (Join-Path $vaderTestRoot 'run02.sql')
Invoke-VaderTestSql -File (Join-Path $vaderTestRoot 'verify.sql')
```

Expected: two NOLOGIN/non-superuser/NOBYPASSRLS roles; two new private/API schemas;
two private tables; original five table owners unchanged; 59 target columns and
33 target constraints (two generated risk columns and two FKs), still 15 indexes;
all definer search_paths pinned; only vader_ingest entry EXECUTE; no private helper
EXECUTE/table rights for callers; no schema CREATE left for writer owner. Inspect
private.principals too: if a replicated event trigger enabled RLS without a writer
SELECT policy, tenant lookup may fail. Record failure and revise, not disable RLS.

TEST-only provisioning, admin psql session (no password literals):

```sql
CREATE ROLE vader_tenant_a_test LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
CREATE ROLE vader_tenant_b_test LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
CREATE ROLE vader_unmapped_test LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
GRANT vader_ingest TO vader_tenant_a_test,vader_tenant_b_test,vader_unmapped_test
 WITH INHERIT TRUE, SET FALSE;
\password vader_tenant_a_test
\password vader_tenant_b_test
\password vader_unmapped_test
INSERT INTO vader_private.principals(principal_oid,principal_name,organization_id,enabled)
 SELECT oid,rolname,'11111111-1111-4111-8111-111111111111'::uuid,true
 FROM pg_roles WHERE rolname='vader_tenant_a_test';
INSERT INTO vader_private.principals(principal_oid,principal_name,organization_id,enabled)
 SELECT oid,rolname,'22222222-2222-4222-8222-222222222222'::uuid,true
 FROM pg_roles WHERE rolname='vader_tenant_b_test';
```

pg_roles must return exactly one row for each intended binding. Leave unmapped
unbound. Provisioning is separate from proposal 02 and only allowed in TEST.

```powershell
Invoke-VaderTestSql -Role vader_tenant_a_test -Sql 'SELECT current_user,session_user;'
Invoke-VaderTestSql -Role vader_tenant_b_test -Sql 'SELECT current_user,session_user;'
Invoke-VaderTestSql -Role vader_unmapped_test -Sql "SELECT vader_api.read_history_v1('synthetic-actor','2026-01-01T00:00:00Z','2026-01-01T01:00:00Z');"
```

Expected: session_user is the actual custom LOGIN in each case; unmapped history
fails with 42501. Calling as postgres or through PostgREST must NOT be accepted as
a substitute. Failure to authenticate is a hard blocker for this writer design.

## 7. Writer fixtures and exact execution pattern

Prepare two local `bundle_a.json` / `bundle_b.json` synthetic fixtures after
approval, never under committed application configuration. Use four events with
event_time at 00:00, 00:01, 00:02, 00:03 UTC on 2026-01-01; source
`vader-test-v1`, stable external_event_id `a-0`..`a-3` / `b-0`..`b-3`, same
actor `synthetic-actor`, source_ip `192.0.2.10`, details respectively:

```json
[{"failed_attempts":5},{"authorized":false},{"authorized":false},{"bytes_transferred":1000000000}]
```

Match event_type order login, privilege_escalation, sensitive_resource_access,
data_transfer. Generate finding explanations/evidence and risk factors with the
existing pure Python engines, then explicitly map DTOs using vader-schema-mapping.
Required title and versions: detector `vader-detector-v1`, correlation
`vader-correlation-v1`, risk `vader-risk-v1`. Set evidence.detector_version,
summary.ordered_event_ids/correlation_version and factors.input_revision as
documented. Do not feed whole Phase 1 dumps to the writer: unknown keys are rejected.
Use request_key `fixture-a-v1` / `fixture-b-v1`. Findings' source_event_id and risk
subject_id need exact server-compatible deterministic UUIDs before the call.

**Fixture preparation gate:** no executable fixture generator is supplied by
this plan. After approval, build/review the two fixtures using the existing pure
engines and compare UUID vectors with an admin SELECT of extensions.uuid_generate_v5
using the exact id_v1 expression. Do not grant callers EXECUTE on the private helper
just to compute IDs. Cross-language canonicalization mismatch stops this test.
The fixture request body contains no organization key, arbitrary entity id,
incident_number, timestamps owned by the DB, or status fields.

For exact fixture identity vectors, an admin SELECT (TEST only) is:

```sql
SELECT extensions.uuid_generate_v5(
 '95980ed1-c0d3-5b64-90cc-9ea71f7b0385'::uuid,
 jsonb_build_array('mesh-vader-storage-v1','event',
   '11111111-1111-4111-8111-111111111111'::uuid,
   jsonb_build_array('vader-test-v1','a-0'))::text
) AS event_a0_id;
```

To execute a reviewed JSON fixture, build a TEST driver script containing literal
synthetic JSON, not shell-interpolated credentials. This local staging pattern
works with either bundle; the function supplies the current history revision:

```powershell
$fixturePath = Join-Path $vaderTestRoot 'bundle_a.json'
$fixtureJson = Get-Content -LiteralPath $fixturePath -Raw
$null = $fixtureJson | ConvertFrom-Json
if ($fixtureJson.Contains('$fixture$')) { throw 'Unsafe fixture delimiter' }
$driver = @'
BEGIN;
SET LOCAL lock_timeout='3s';
SET LOCAL statement_timeout='15s';
SET LOCAL idle_in_transaction_session_timeout='60s';
SELECT vader_api.read_history_v1('synthetic-actor','2026-01-01T00:00:00Z','2026-01-01T01:00:00Z') AS history \gset
SELECT vader_api.commit_bundle_v1(jsonb_set(
 $fixture$__SYNTHETIC_JSON__$fixture$::jsonb,
 '{history_revision}',(:'history'::jsonb)->'revision')) AS result;
COMMIT;
'@
$driver = $driver.Replace('__SYNTHETIC_JSON__',$fixtureJson)
Set-Content -LiteralPath (Join-Path $vaderTestRoot 'bundle_a_driver.sql') -Encoding UTF8 -Value $driver
Invoke-VaderTestSql -Role vader_tenant_a_test -File (Join-Path $vaderTestRoot 'bundle_a_driver.sql')
```

The JSON must contain all required top-level fields/arrays; this driver replaces
only history_revision. For a byte-identical retry, **do not rebuild the request
with a newly read revision after the first commit**: the receipt compares the
entire request payload. Capture the exact submitted body locally, then retry it
unchanged. A changed history revision with the same request_key must conflict.
Expected initial A success: 4/4/1/4/5 application rows for A and no B rows, unless
testing A/B order after a prior approved fixture. Identity numbers may have gaps.

## 8. Writer security, rollback, retry and concurrency cases

Execute each case in a fresh test transaction/fixture namespace unless its purpose
is replay. Do not permanently modify real helper bodies or weaken the writer to
make tests pass. Store SQLSTATE, expected/actual counts and safe result IDs locally.

| Case | Concrete action | Expected |
| --- | --- | --- |
| Role isolation | A/B actual LOGIN; direct SELECT/INSERT on application/private tables; private helper call; SET ROLE vader_writer_owner | Denied. Only public entry functions allowed; no cross-tenant history |
| Identical actors | Commit fixture B using B's session after A fixture | B sees only B; row counts independently 4/4/1/4/5 |
| Payload spoof | Add organization_id or arbitrary id to an entity | Unknown-field rejection; no rows/receipts committed |
| FK escape | A finding references B event; A incident links B event; A score references B finding/incident UUID | Rejected; entire bundle rolls back |
| Global risk enforcement | Admin transaction attempts A score pointing to B/nonexistent subject, updates an existing subject, or deletes referenced parent | New FKs reject; transaction rolled back. Asset/identity are explicitly outside this guarantee |
| Disabled binding | Admin temporarily sets A binding enabled=false, then A calls history | 42501; restore only TEST binding afterwards |
| Role reuse | In a separate synthetic test role, disable/drop/recreate role then authenticate | Old OID binding cannot authorize recreated identity; A/B fixture logins not casually dropped |
| Helper semantics | Controlled authenticated-role transactions with synthetic JWT sub for active A, B, suspended A and outsider | is_mesh_member true only for authorized active scopes; SQL impersonation is helper unit testing, not proof of real custom login |
| History bounds | NULL/wrong actor, >120-minute range, >1,000 synthetic events, out-of-window event | Rejected/limited per proposal; no silent truncation |
| Chain validation | Duplicate IDs, equal/reversed timestamps, missing stage, benign stage, >60-minute chain | Rejected; no links/incidents retained |
| Typed input | Strings/booleans/fractions/negative counters, nonboolean authorization, invalid inet, missing timezone | Rejected with no partial outputs |
| Same committed request | Exact saved request bytes/body and same key after COMMIT | Same IDs, unchanged counts/status/timestamps/numbering; receipt returns prior result |
| New request/shared entities | New request_key/revision but identical mapped entities | One additional bundle receipt only; no new entity rows |
| Immutable conflict | Same event source/upstream ID with changed details, or same entity identity with changed evidence | Conflict, no silent overwrite |
| Investigation preservation | Admin updates TEST finding/incident status, then replay | Status/assignment/triage not reset |
| Caller ROLLBACK | Valid bundle in transaction ending ROLLBACK, then admin count | No application/receipt rows from that request; sequence gaps allowed |
| Unknown commit outcome | Commit a fixture and intentionally discard response, reconnect, replay exact saved request | One set of rows; successful cached response |

Fault injection after each stage: use a TEST-only trigger function on each target
table in turn that raises an exception for the fixture namespace. Trigger on
finding insert (after events), incident insert (after findings), link insert
(after incident), score insert (after links), and receipt UPDATE (after scores).
Write/review those test-only trigger snippets after execution approval; do not
edit the migration function body. Assert all new rows and receipts roll back,
then remove only that synthetic trigger/function. This is stronger than merely
testing an invalid first event. Test existing rows/triage remain unchanged too.

Concurrency requires TWO real custom-login terminals, plus optional admin observer:

```sql
-- Terminal A, real tenant A login (keep open while running terminal B):
BEGIN;
SELECT vader_api.read_history_v1('synthetic-actor','2026-01-01T00:00:00Z','2026-01-01T01:00:00Z');
-- Do not COMMIT until B has attempted its call. Complete within 60 seconds.
```

```sql
-- Terminal B, another connection as tenant A:
BEGIN;
SET LOCAL lock_timeout='2s';
SELECT vader_api.read_history_v1('synthetic-actor','2026-01-01T00:00:00Z','2026-01-01T01:00:00Z');
-- Expected lock timeout 55P03 while A holds lock; then ROLLBACK.
```

Repeat terminal B using tenant B: expected immediate success despite A's held lock.
ROLLBACK both. Then run two same-tenant concurrent identical-bundle commits:
one serializes after the other, both return the same IDs, no duplicate rows.

Stale-revision test: connection 1 reads history in autocommit and saves revision;
connection 2 commits a new same-actor event within that range; connection 1 submits
a NEW request_key with its saved revision. Expected 40001, no new rows/receipts.
Reload/recompute with a new request key for a changed body. The explicit
transaction read/compute/write test must hold its lock across computation.

## 9. Evidence, teardown and confidence limits

Record a table of test ID, project reference, PostgreSQL/extension versions,
proposal hashes, actual SQLSTATE, before/after row counts and pass/fail. Keep
secrets and raw sensitive helper definitions out of the evidence bundle. Capture
new post-02 columns/constraints/policies/ACLs and verify proposed roles are never
members of postgres/service_role. Show guard/rollback tests before happy-path results.

Stop immediately on unexpected target, unknown schema, paid quota, unsupported
role creation/ownership transfer, authentication failure or tenant leakage. Do not
relax guards, grant ALL, use global service credentials or change MESH as a workaround.

After results are reviewed, obtain approval to delete the disposable project in
Dashboard. Do not run reset/truncate/drop-cascade against MESH or relink the repo.
Remove only the named temporary directory and local TEST credentials after evidence
retention is agreed. Do not automatically delete a project as part of the test run.

Differences limiting confidence:

- New project PostgreSQL minor/major, extension versions, managed memberships,
  event-trigger setup and default grants may differ. Major !=17 blocks proposals.
- Missing full helper source or a stubbed/minimal schema means authorization tests
  are incomplete; ten-table tests do not prove all-18-table interoperability.
- Synthetic data cannot establish production duplicate/orphan counts, FK validation
  duration, rewrite locks, throughput, retention costs or migration downtime.
- New tiny Free compute and a few sessions are functional tests, not load benchmarks.
- SQL Editor/helper impersonation does not prove backend custom-login capability;
  the exact pooler/driver/transaction mode must be tested with real logins.
- Private schemas may interact differently with the production rls_auto_enable
  event trigger; preserve/review that behavior instead of disabling it silently.
- Actual SDK/frontend exposure, secret delivery, credential rotation, network access
  and source authenticity require separate application/operations verification.
- A successful test migration does not reconcile production's empty migration
  history or authorize production application.

## Approval requested before execution

Approve creating one Free disposable project (if a free slot exists), using Windows
psql, loading the reviewed schema-only application source, provisioning synthetic
users/logins/data and running this test matrix only there. First supply/review the
missing schema/helper sources; fixture/trigger test scripts will then be prepared
and inspected before execution. Production MESH, its permissions and migrations
remain excluded. Any paid service, production access or production migration
requires separate approval.
