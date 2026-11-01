# Disposable TEST bootstrap ? revised after actual preflight

Allowed TEST: **ikmzxirldivefebgxzaa**. Protected production: **khweikfvsnervfuswhon**.
Preparation/review only; no SQL executed by this revision. Files remain outside
migrations/. No repository relinking or linked Supabase CLI command is used.

## Actual test evidence

preflight_result.json proves PostgreSQL 17.11, postgres database/session/user,
read-only transaction, native roles/extensions/functions, public CREATE for the
operator, and no application-table/enum/proposal-role/schema conflicts. The user
ran it through the verified TLS pooler route. The server exposes no independent
project-ref setting; project selection rests on the supplied TEST endpoint and
exact postgres.ikmzxirldivefebgxzaa username, not current_database() alone.

The only native public helper is rls_auto_enable, postgres-owned, SECURITY DEFINER,
with captured definition MD5 846ec2fbff751d24b890656d63c3a9bf. Native ensure_rls
already has the exact captured owner, handler, origin-enabled state and CREATE
TABLE / CREATE TABLE AS / SELECT INTO tags. No event-trigger creation is needed;
the operator is not a superuser and the revision requires none.

## Artifacts

| File | Purpose |
| --- | --- |
| bootstrap_test_only.sql | Guarded single-transaction, schema-only reconstruction |
| build_bootstrap.py | Offline deterministic generator; pinned production captures AND TEST preflight |
| validate_bootstrap.py | Offline schema/safety/hash/lexical regression checks, no SQL execution |
| fidelity_manifest.json | Source/output hashes, actual TEST facts, counts and all deviations |
| Invoke-TestDatabase.ps1 | Fixed-target launcher; LOCAL --version default; verify-full and password prompt |
| target_guard.psql | Client route check; not an independent server identity oracle |
| connection_check.sql | Read-only preflight metadata query |
| verify_schema.sql | Read-only post-bootstrap catalog verification |
| synthetic_tenants.sql | Separate optional guarded two-tenant seed, not called by bootstrap |
| BOOTSTRAP_EXECUTION_REVIEW.md | Current GO/NO-GO decision and runtime limitations |

## Exact schema/fidelity

18 empty application tables, 165 columns, 85 constraints, 46 indexes, 18 RLS
policies and two enums are reconstructed from captured metadata. Key constraints
create 29 indexes; the other 17 are replayed exactly. Existing composite tenant
FKs are retained. Every application table remains postgres-owned, RLS enabled and
not forced. No production data/credentials or Auth users are copied.

Two NEW application helpers are created only after checking their names are absent:
handle_new_mesh_user and is_mesh_member. Their bodies, security modes, pinned
search paths and argument/default semantics come from the source capture; they
are owned by the creating postgres user, so no ALTER FUNCTION OWNER is needed.
ACL changes target only these NEW functions and NEW application tables/sequence.

Native rls_auto_enable is REQUIRED and verified/reused, with no CREATE/ALTER/GRANT/
REVOKE targeting it. ensure_rls is REQUIRED and verified/reused, with no event-
trigger DDL. No existing schema ACL, managed role/membership or creator default
ACL is changed. Missing API public USAGE or native compatibility causes an early
failure, not a privilege grant or fallback recreation.

The bootstrap snapshots native schema ACL/ownership, key native routine definitions/
ACL/owners, event triggers, roles/memberships/default ACLs, auth.users ACL/owner and
its noninternal triggers in a transaction-local GUC. It compares them before COMMIT
and aborts if they changed. No audit table or temporary function is installed.

**Auth provisioning deviation:** on_mesh_auth_user_created is NOT attached to
managed auth.users. The captured handle_new_mesh_user function remains available
as an unattached application helper. Later synthetic users must be created via
TEST Auth and have explicit TEST profiles/memberships seeded before authorization
helper tests. Automatic Auth-to-profile provisioning is not covered by this fixture.
Do not alter auth.users or attach a trigger merely to make old test steps pass.

**Necessary FK bookkeeping:** new public FKs referencing auth.users are preserved.
PostgreSQL creates internal referential-integrity triggers/dependencies on referenced
relations, including auth.users. The fixture therefore is not a literal zero-system-
catalog-change clone. It adds no application Auth trigger, alters no Auth columns,
permissions or data, and preserves existing noninternal Auth triggers. Internal RI
triggers are deliberately excluded from the native noninternal-trigger snapshot.

**Sequence exception:** the damaged source max 9223372036854776000 is NOT replayed.
The TEST ALWAYS bigint identity uses max 9223372036854775807, START/INCREMENT/MIN/
CACHE 1, NO CYCLE and the captured sequence name. No production counter is restored.
This is PostgreSQL-compatible, not proof of the exact lost production maximum.

Current-object grants intentionally reproduce the dangerous original baseline on
NEW disposable tables so migration 01 can be tested. This is not a hardened schema
for production. Native default/type ACLs, physical storage/collation options and
managed-platform configuration are not cloned. The two source captures are not one
atomic whole-database snapshot. Source hashes and exceptions are in the manifest.

## Execution plan ? commands prepared, not executed

Client path verified locally: C:\Program Files\PostgreSQL\18\bin\psql.exe, version
18.6. Server 17.11 is compatible; client major version does not change the server.
TLS CA was previously validated and a verify-full-equivalent TLS-only handshake
succeeded. No password is stored in this folder. Use your OWN interactive PowerShell
if the agent-launched password terminal cannot accept input; do not pipe its stdin.

The successful preflight is already saved; no repeated inspection is required solely
for this review. On a future explicit instruction to execute the TEST bootstrap:

```powershell
$runner = Join-Path (Get-Location) 'supabase/testing/ikmzxirldivefebgxzaa/Invoke-TestDatabase.ps1'
$testHost = 'aws-0-eu-west-1.pooler.supabase.com'
$testCa = 'C:\Users\APOORV\Downloads\prod-ca-2021.crt'
# MUTATING TEST-ONLY step: run ONLY after explicit execution approval.
& $runner -Action Bootstrap -ApproveBootstrap -TestHost $testHost -RootCertificate $testCa
# Review successful completion before this separate read-only verification:
& $runner -Action VerifySchema -TestHost $testHost -RootCertificate $testCa
```

The launcher pins TEST username/database/port, clears inherited libpq routing,
requires verify-full and CA file, checks the manifest byte hash, prompts for the
password, and restores environment variables afterwards. Production is not an
allowed destination. Do not execute isolated SQL or edit guard variables to bypass
these controls. Current_database alone is not project identity proof.

Schema verification should show 18/165/85/46/18, two new application helpers plus
one unchanged native helper/event trigger, and NO Auth application provisioning
trigger. Compare definitions/grants, not just totals. Synthetic seeds and proposals
01/02 are separate and are not invoked automatically. A schema error must STOP;
there is no reset, cleanup, managed-object recreation or automatic retry.

## Local regeneration and checks (no SQL/network)

```powershell
.\azure\security\vader\.venv\Scripts\python.exe supabase/testing/ikmzxirldivefebgxzaa/build_bootstrap.py
.\azure\security\vader\.venv\Scripts\python.exe supabase/testing/ikmzxirldivefebgxzaa/validate_bootstrap.py
```

The generator writes fixed LF bytes so PowerShell Get-FileHash agrees on Windows.
After future checkout normalization, regenerate/review rather than disabling hash
validation. New source/preflight hashes require an intentional generator review.

## Decision and limits

GO for ONE guarded disposable TEST bootstrap execution attempt after explicit
execution instruction; no remaining identified native-object conflict requires a
new SQL inspection. This is not a production/migration/writer release approval.

SQL/PLpgSQL compilation has not run. Before any DDL, the script rechecks REFERENCES
on auth.users and API schema USAGE (not separately enumerated in the saved preflight),
all native fingerprints/configuration and a clean application namespace. These may
fail safely without granting privileges. Native snapshot differences, unsupported
DDL or platform drift abort the transaction. Runtime user/tenant isolation,
concurrency, rollback and idempotency remain subsequent disposable tests, not
assertions of this static review. The previous stale agent preflight_status.json
is not evidence against the successful manual preflight_result.json.
