# Independent-review blocker corrections — 2026-10-31

**GO for another independent LOCAL review. NO-GO for database execution.**
The runtime gate remains false. No database connections, SQL, grants, migrations,
fixtures or runtime harness executions occurred. No historical evidence/baselines
were modified. The previous Phase 2 preparation pins were archived, not discarded.

## 1. Narrow extensions access

The machine candidate grants only schema USAGE on extensions to vader_writer_owner
for UUIDv5 and digest name resolution. It grants neither CREATE nor grant options,
adds no PUBLIC access and changes no native function ACL. An effective prerequisite
still checks existing extension function EXECUTE. This is narrower than new
privileged UUID/digest helpers, which would expand the SECURITY DEFINER surface.
The exact ACL oracle admits one extensions tuple only; all other native schemas
and native functions retain their original permissions. Rollback compares the
whole captured tuple set, and fresh cleanup verifies its original fingerprint.

## 2. PostgreSQL 17 creator roles and ownership

SET LOCAL createrole_self_grant='set,inherit' precedes only creation of the three
new roles. The trusted postgres operator receives SET for ownership transfers and
INHERIT for subsequent owner-authorized GRANT/REVOKE. No existing role attributes
or pre-existing memberships change. This does NOT grant writer-owner membership
to API roles, tenant logins or application users.

Importantly, this setting creates TWO rows per role, rather than modifying the
automatic administrator row. Exact assertions admit six new rows only:

| Grantor | Member | Role | ADMIN | INHERIT | SET |
|---|---|---|---|---|---|
| bootstrap OID 10 | postgres | each new VADER role | true | false | false |
| postgres | postgres | each new VADER role | false | true | true |

All old pg_auth_members rows, including OIDs and options, remain byte-equivalent
JSON tuples. Duplicate/missing/extra edges or different options/grantors fail.
SET/INHERIT capability is checked before transfers; exact function ownership is
verified afterward. Role and membership DDL remains in the rollback transaction;
post-rollback metadata/fresh cleanup require the original role inventory and edges.
GUC changes are transaction-local, never ALTER ROLE/ALTER SYSTEM settings.

Reference: [PG17 creator setting](https://www.postgresql.org/docs/17/runtime-config-client.html#GUC-CREATEROLE-SELF-GRANT)
and [PG17 role-creation implementation](https://github.com/postgres/postgres/blob/REL_17_STABLE/src/backend/commands/user.c).
The source separately records bootstrap ADMIN and current-user INHERIT/SET grants.

## 3. Exact permission oracle

capture_acl.sql records explicit tuples: object kind, fully identified object,
column, grantor, grantee, privilege and grant option. Scope includes every public
and private table/column/sequence, public/extensions/new schema ACLs, and new
private/API functions. Existing native functions and other managed schemas remain
covered by the original unchanged metadata checks.

acl_contract.json specifies 145 exact additions independently of parsing SQL GRANT
statements. Its only removals are the approved dangerous audit-table grants to
PUBLIC/anon/authenticated/service_role. Every other original tuple must survive.
assert_acl_exact.sql emits unexpected/missing tuples before raising. No approved-
table exception permits arbitrary column SELECT or other ACL changes. PUBLIC
access, function grant options, changed grantors, new private access and missing
legitimate grants all fail equality. Existing effective-permission and raw-ACL
checks remain additional defenses; function definitions/owners are still checked.

The rollback driver stores the pre-attempt ACL set before its savepoint and demands
exact equality after rollback. Fresh cleanup reads its fingerprint from hash-
verified runtime evidence. Failed runtime status is not converted to PASS by
cleanup. Missing/ambiguous baseline evidence requires separate investigation.

## Files changed

Modified proposal preparation: build_candidates.py; generated 03_machine_writer.sql
and 04_human_triage.sql plus their .body.psql versions; CONTRACTS.md and REVIEW_REPORT.md.
Added build_acl_contract.py and acl_contract.json. Function-body/object manifests
were regenerated and remain unchanged where content was unaffected.

Modified harness: runtime.sql, cleanup_check.sql, assert_delta.sql,
Invoke-WriteRollback.ps1, validate_offline.py, README.md, execution_readiness.json
and preparation pins.json. Added capture_acl.sql, generated assert_acl_exact.sql,
assert_memberships.sql, acl_model.py, acl_negative_tests.py and the explicit local
update_preparation_pins.py tool. The machine-readable changed_preparation_files.json
records exact changed paths and before/after hashes. A review_archive retains the
previous preparation manifest. Existing R2/read and Phase 1 files are unchanged.

## Offline validation and limits

35 tests pass: 12 original contract models, 9 Phase 2 models, 14 new ACL/membership
tests. Intentional in-memory mutations cover column SELECT without table SELECT,
service_role/PUBLIC/private-table reads, schema CREATE/USAGE, grant options on
table/column/schema/function/sequence, wrong grantors, missing dependency grants,
old-grant removal, duplicate tuples, altered creator edges and incomplete rollback.
All such unexpected permissions are rejected by the pure tuple oracle.

Static validation checks generated body equivalence, SQL include closure, closed
runtime gate, rollback-only flow, new exact assertions and pinned historical files.
PowerShell AST parsing passes; the launcher was not invoked. Python emits a local
location warning but all validations execute. No PostgreSQL parser is installed.

These are models/static checks, not PostgreSQL execution proof. Supabase's ability
to set this PG17 GUC, automatic grantor behavior/owner transfer, ACL grantor choice,
MAINTAIN default ACLs, TOAST counts and deparser formatting require separately
authorized runtime validation. The bootstrap OID is deliberately checked, not
silently normalized. Unexpected behavior must stop without broadening permissions.
Native event triggers remain enabled and unchanged. Real LOGIN, JWT and concurrent
database sessions remain outside this rollback tier. Business status/assignment/
audit-retention contracts still require review. No runtime gate was enabled.
