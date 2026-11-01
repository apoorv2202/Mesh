# Bootstrap execution review ? native-preserving revision

Date: 2026-10-29. TEST only: ikmzxirldivefebgxzaa.
**GO for one guarded disposable bootstrap attempt after explicit execution approval.**
No SQL, migration, bootstrap, production access, deployment, commit or push occurred.

## Evidence validated

The actual preflight_result.json is present and parsed; SHA-256:
`b029522ac959950eccf9f61a5bc19be799e869f1e0df40175e458612c8dc5e72`.
It confirms postgres user/session/database, read-only transaction, PostgreSQL 17.11,
public CREATE/USAGE for the operator, native auth/extension function EXECUTE,
no application table/enum/proposal-role/schema conflicts, and no Auth trigger conflict.
Native roles and Supabase-managed memberships are recorded. postgres has CREATEROLE
and BYPASSRLS but is NOT superuser. Client 18.6 was verified separately locally.

Existing public helper rls_auto_enable has EXACT expected captured definition MD5
846ec2fbff751d24b890656d63c3a9bf, postgres owner and definer mode. Existing ensure_rls
is enabled O, ddl_command_end, postgres-owned, bound to that helper, with exactly
the three captured DDL tags. The old missing-helper/event-creation blockers are
resolved by the saved evidence and reuse-only revision, not by relaxed guards.
The server project-ref setting is NULL: project attribution remains based on the
user-verified TLS route and fixed TEST pooler username, not an independent SQL ID.

Revised bootstrap SHA-256 (actual bytes):
`02b3dc6c26021227cef1a67b2591e0277b1d2c8b0ba059cdcb92d62599eb5fc4`.
Its source hashes and expected object counts are pinned in fidelity_manifest.json.
The original failed agent-window status file is historical; it does not supersede
the successful manual preflight. No repeat inspection is requested for proven facts.

## Managed-object conflicts resolved

| Previous issue | Revised behavior |
| --- | --- |
| ALTER owner and REVOKE/GRANT on an existing native helper | No native function DDL/ACL statements emitted; verify and reuse rls_auto_enable only |
| CREATE EVENT TRIGGER under a non-superuser | Removed entirely; require exact existing ensure_rls, otherwise abort before DDL |
| GRANT USAGE on public schema | Removed; existing namespace ownership/ACL preserved; expected privileges checked |
| Auth application trigger attached to auth.users | Omitted; existing noninternal Auth triggers preserved; explicit synthetic profiles are required later |
| Existing helper name could be reused/altered | is_mesh_member/handle_new_mesh_user must be absent; only new application functions are created, with captured source ACLs |
| Preservation asserted only by code inspection | Future execution snapshots native roles/memberships/defaults, schema ACLs, native routines, event triggers and Auth noninternal triggers/ACLs; mismatch before COMMIT aborts |

No CREATE/ALTER ROLE, managed membership operations, extension installation, existing
native owner transfer, schema GRANT/REVOKE, native event DDL or native function ACL
changes remain. No GRANT ALL or RLS bypass is introduced. The application baseline
still intentionally has the captured dangerous table grants for migration-01 tests.

The fixture still creates public FKs referencing native auth.users. PostgreSQL
necessarily installs internal RI triggers/dependencies on referenced relations.
This is required to preserve the captured FK/tenant model and is explicitly not a
zero-catalog-change claim. No Auth data/columns/permissions or application Auth
trigger is modified. Native noninternal trigger preservation is checked separately.

## Counts, identity and fidelity

18 tables / 165 columns / 85 constraints / 46 indexes / 18 policies / two enums
remain unchanged. Two application helpers are created; one native helper and one
native event trigger are reused unchanged. Application Auth trigger creation count
is now ZERO. No production or synthetic data is loaded by the schema bootstrap.

Identity is bigint GENERATED ALWAYS, named original sequence, START/INCREMENT/MIN/
CACHE 1, NO CYCLE, bounded max 9223372036854775807. The exported out-of-range max
is never replayed. Exact production sequence maximum/current value is not claimed.
No sequence setval or new numbering function is used.

Automatic Auth-to-profile provisioning is intentionally NOT tested. Create synthetic
users via TEST Auth later and explicitly seed public.profiles/organization_members
using those TEST UUIDs. Do not attach the omitted trigger to make the older test
plan's provisioning expectation pass. Trigger function body remains available as
an unattached application helper; future provisioning tests need separate review.
Native role graphs/default ACLs/type ACLs, physical options/collation and production
data are not copied. The fixture is not an identical production clone or baseline.

## Runtime conditions, not yet-proven outcomes

Before application DDL the bootstrap rechecks exact user/server/native helper and
event configuration, name conflicts, public CREATE/USAGE, API public USAGE, auth
schema USAGE and auth.users REFERENCES. The saved preflight confirms operator
public CREATE/USAGE and auth USAGE, but does not separately enumerate API USAGE
or auth REFERENCES. Those checks deliberately fail closed instead of issuing a
grant if a required permission is absent. No new inspection is needed merely to
prepare the guarded attempt; failure must stop execution and prompt review.

New application functions are created as postgres, eliminating redundant ownership
transfer. Native functions and event triggers are never recreated. DDL, application
ACLs and preservation snapshots share one transaction; errors/postflight mismatches
prevent COMMIT. The reviewed launcher controls route/TLS/password prompting/hash
and requires an explicit Bootstrap approval switch, with no automatic migration run.
Client-supplied route guards are not a magical database identity oracle; never
paste isolated DDL or use linked CLI commands.

## Static validation and final decision

Offline generator/source/hash, Python AST, PowerShell parser, SQL lexical checks,
exact application constraint/index/policy correspondence and native-preservation
regression assertions pass. Deterministic regeneration must retain the same hash.
No PostgreSQL SQL/PLpgSQL parsing, compilation or runtime execution occurred.

**GO: controlled TEST-only bootstrap attempt through the unchanged guarded launcher,
after an explicit execution instruction.** No currently identified managed-object
conflict remains. This approves the revised design for a disposable attempt, not
a guarantee that every DDL statement will succeed or that runtime isolation works.

**NO-GO: production, proposals 01/02, custom-login/writer release, or automatic
follow-up execution.** They are outside this review's execution scope. Successful
bootstrap must first be followed by read-only schema/native-preservation validation;
then the existing disposable migration test matrix remains to be performed.
