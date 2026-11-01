# Read-only TEST preflight — blocked before database authentication

Target: ikmzxirldivefebgxzaa. Protected production: khweikfvsnervfuswhon.
Date: 2026-10-29. **Bootstrap execution decision: NO-GO.**

No bootstrap, migration, seed, remote SQL, database login or production access
was performed. Only local artifact checks and TEST-only DNS/TLS probes occurred.
The read-only connection_check.sql was expanded locally to collect complete
extension, role/schema permission and object-conflict metadata when authentication
becomes possible. Bootstrap/proposal contents and manifest were not changed.

## Completed checks

| Check | Evidence / result |
| --- | --- |
| Explicit target separation | Manifest allowed ref is ikmzxirldivefebgxzaa; protected ref differs; launcher hard-codes TEST routing and has no linked CLI invocation |
| Repository link | Still production, read locally only; neither changed nor used |
| Bootstrap integrity | Actual-byte SHA-256 agrees with fidelity manifest |
| Local client | Existing supplied psql path; prior local --version verified 18.6 |
| TEST direct hostname DNS | Resolve-DnsName succeeded for db.ikmzxirldivefebgxzaa.supabase.co, AAAA 2a05:d018:1b65:3000:831b:7480:b562:f4ff |
| DNS sandbox behavior | Initial restricted lookup denied; authorized outside-sandbox TEST-only lookup succeeded |
| TLS probe | Python standard TLS client required certificate/hostname verification; getaddrinfo failed (11001) before connection/SSL negotiation |
| Authentication | Not attempted; no configured secure credential source discovered |
| Production effects | None; only TEST hostname was probed |

DNS existence does not prove project identity or certificate validity. The TLS
failure establishes neither certificate rejection nor an invalid project: the
probe never reached the handshake. Do not lower sslmode to troubleshoot it.
The direct endpoint is IPv6; the TEST session-pooler endpoint may be needed for
this workstation. Its actual hostname must come from the TEST Connect panel.

## Missing connection prerequisites

No PGHOST/PGUSER/PGDATABASE/PGSSLMODE/PGSSLROOTCERT, secure password/passfile/service
configuration, or named VADER/Supabase TEST host/password settings were present in
the agent process. The standard Windows PostgreSQL credential/certificate folders
were absent. No certificate file was found in the repository. Secret values were
not printed or read from an unrelated production configuration.

Needed: hostname from TEST Connect / Shared Session Pooler (port 5432), absolute
local path to the trusted TLS CA certificate, and TEST database authentication
through a secure local source or an interactive password prompt. Do not send a
password, API key or credential-bearing URI in chat. Do not guess a pooler region.

## Not verified against the live TEST database

- PostgreSQL server version. Client 18.6 does not prove server major 17 compatibility.
- Installed extension versions and extensions.uuid_generate_v5/digest availability.
- Native auth/users/uid existence and current role/table/schema/sequence grants.
- Authority for CREATE TABLE/TYPE/FUNCTION, Auth-trigger attachment, owner/ACL
  operations or event-trigger creation. SELECT metadata cannot prove every DDL.
- Existing application tables/enums/proposal roles/schemas, helper fingerprints,
  ensure_rls handler/tags/status and native-role membership differences.
- Any runtime RLS/tenant isolation, retry, idempotency, FK or transactional behavior.

These facts must not be inferred from the production capture or reported as
passing. connection_check.sql now covers metadata prerequisites/conflicts with
catalog SELECTs in an explicit READ ONLY transaction; it still executes no helper
bodies or capability-test DDL. Missing or restricted catalogs can cause a failure.

## Managed-object boundary: static finding requiring review

The bootstrap avoids copying managed schemas/data and never alters managed role
memberships, but it does NOT make zero managed-object changes:

1. It attaches on_mesh_auth_user_created to auth.users. This is an application
   trigger on a managed table, not a clone of auth.users; it still changes that
   table's trigger configuration and requires the corresponding permission.
2. It reasserts owner/EXECUTE ACLs for captured public helpers even when matching
   native helpers are reused. Equality of body/owner does not prove every native
   ACL matches; a native rls_auto_enable ACL could therefore be changed.
3. It grants captured public-schema USAGE and may create ensure_rls if absent.
   Standard PostgreSQL requires superuser to create event triggers; the production
   postgres role is not a true superuser. Native TEST reuse/managed restrictions
   are unknown until the read-only result is reviewed.

Therefore a claim that the current bootstrap runs without modifying any
Supabase-managed objects is not supported. Review the Auth trigger and native
helper/schema ACL scope explicitly, or revise the TEST fixture under separate
instructions to preserve native objects and document lost test coverage. Do not
silently replace a mismatched helper, disable RLS, grant managed-role membership
or skip event-trigger checks to force successful bootstrap execution.

## Exact next action (read-only only)

Provide the non-secret TEST session-pooler hostname and trusted local CA path,
and arrange interactive/secure local TEST authentication. The prepared command
can instead be run in a local PowerShell terminal where its password prompt is
visible to the user:

```powershell
$runner = Join-Path (Get-Location) 'supabase/testing/ikmzxirldivefebgxzaa/Invoke-TestDatabase.ps1'
$testHost = Read-Host 'Hostname only from TEST project Connect / Session pooler'
$testCa = Read-Host 'Absolute local path to trusted TEST TLS CA certificate'
& $runner -Action ConnectionCheck -TestHost $testHost -RootCertificate $testCa
```

This action uses verify-full, explicit TEST username/database/port, sanitized
inherited routing/options and a password prompt. It does not enable any bootstrap
gate. Return the JSON result or reviewed error. Reassess compatibility and the
managed-object scope before any subsequent execution approval. NO-GO remains
until authentication/TLS/server/object checks and that scope review are complete.
