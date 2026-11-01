# VADER disposable testing — Stage 1 results

Updated: 2026-10-29, after Stage 2 TEST bootstrap preparation. User authorization
covers preparation only; SQL/bootstrap execution still requires confirmation.
The TEST project was created by the user, not by this agent. No database sessions,
schema loading, users/roles, migrations or permission changes were performed.

## Local checks

| Requirement | Result |
| --- | --- |
| Original three schema scripts | Not found in repository SQL inventory |
| Saved inspection | mesh_inspection.json parses; all 12 sections available |
| Original helper definitions | All three full definitions now recovered from vader_verification.json; earlier mesh_inspection.json still has WITHHELD placeholders |
| Later consolidated result JSON | Present and parsed: 244,237 bytes; complete expected 11-section structure and nested arrays |
| Schema snapshot | supabase/schema_snapshot.sql is zero bytes |
| Prepared TEST bootstrap | supabase/testing/ikmzxirldivefebgxzaa/bootstrap_test_only.sql generated/reviewed offline; not executed |
| Migration directory | No SQL files; only .gitkeep |
| Windows psql | C:\Program Files\PostgreSQL\18\bin\psql.exe verified locally as 18.6 using --version only |
| Environment database routing | PGHOST, PGHOSTADDR, PGUSER, PGDATABASE, PGSERVICE, PGSERVICEFILE, PGPASSWORD and PGPASSFILE absent in this process; values were not printed |
| Current repository project link | Still production khweikfvsnervfuswhon; read locally, not changed or used for a connection |
| Test project reference/endpoint | User supplied ikmzxirldivefebgxzaa; distinct from production. Actual endpoint/TLS/server metadata not yet validated |
| Free-project slot/billing | Account-specific availability not inspected; dashboard check required |

Earlier PATH/client-directory searches are superseded by the newly supplied
absolute psql path and successful local --version result. The 18.6 client version
does not verify the TEST server major version (proposals require PostgreSQL 17).

Original scripts remain unavailable, so their historical contents cannot be
compared. The two saved catalog captures can now support a reviewed TEST-only
schema reconstruction without the originals. A TEST-only bootstrap, fidelity
manifest, guarded launcher and read-only checks are now prepared under
supabase/testing/ikmzxirldivefebgxzaa/. No SQL was executed. The fidelity limits
below remain; the new folder README is the current execution plan.

## Consolidated export validation and comparison

Source: supabase/inspection/vader_verification.json, SHA-256
`70171889939c159a71704d0df4731738361d2a4c53a7d36e5880210b2554bc44`.
Captured 2026-10-29T15:44:14.145446+00:00, PostgreSQL 17.11, database postgres,
current_user/session_user postgres. Project reference is not encoded/verified by
the query; association with MESH still relies on the user's export provenance.

Validation rejected duplicate JSON keys/nonstandard constants and checked all
11 top-level sections, expected nested arrays, helper inclusion and record counts.
The verification format has 11 sections; it is not the older 12-section format.
No expected table/helper/existing role is missing; required extension signatures
and the identity sequence are present; catalog-read checks are true. Missing
vader_ingest/vader_writer_owner and no proposal-schema collisions are expected
before migration. runtime_errors_caught=false describes SELECT error handling,
not a reported runtime error. transaction_read_only=off describes the session,
not evidence of a write by the catalog query.

Compared with mesh_inspection.json and vader-schema-mapping.md:

- Same five tables, 57 columns, 31 constraints, 15 indexes and five SELECT policies.
- Column PostgreSQL types, nullability, defaults, identity/generated flags and
  constraint/index definitions match; policy roles/USING/WITH CHECK match.
- Zero column ACL entries; all 285 role/column effective rows are present.
- All 25 effective role/table rows are present. anon/authenticated/service_role
  retain all four dangerous privileges. Their role attributes are non-superuser;
  service_role has BYPASSRLS. postgres has BYPASSRLS and CREATEROLE, but is not a
  true superuser. CREATEROLE still does not prove every managed ownership operation.
- Managed authenticator memberships in anon/authenticated/service_role are
  SET-enabled but not inherited. They must not be removed to repair table grants.
- Exact helper implementations/defaults/settings and event-trigger registration
  replace the old mapping's withheld-helper uncertainty. Those older statements
  are historical; this report is the current evidence update, not a change to DDL.

### Helper review

| Helper | Verified behavior | Security assessment |
| --- | --- | --- |
| public.is_mesh_member(uuid, mesh_role[]) | SQL/STABLE/SECURITY DEFINER, postgres-owned, empty search_path; role array defaults to NULL; checks public.organization_members organization, auth.uid(), active status and optional role list | Qualified object names and auth-bound identity are appropriate. NULL role list means any active member; empty role array matches none. No automatic Owner override exists: security-team policies do not implicitly admit an Owner. NULL user/org cannot satisfy equality. Runtime/JWT/role tests remain required. |
| public.handle_new_mesh_user() | PL/pgSQL SECURITY DEFINER, postgres-owned, empty search_path; inserts NEW.id and raw_user_meta_data.full_name into public.profiles, ignoring an existing id | No membership/role promotion or dynamic SQL appears. full_name is user-controlled display data, not trusted authorization; consumers must handle it safely. The body itself supplies no organization membership. |
| public.rls_auto_enable() | PL/pgSQL SECURITY DEFINER, postgres-owned, search_path=pg_catalog; inspects CREATE TABLE/CREATE TABLE AS/SELECT INTO and enables RLS only on public tables, using quoted identifiers | Identifier quoting/pinned path are appropriate. Exceptions are caught and logged, so successful DDL is not proof RLS was enabled. It does not FORCE RLS or create policies. The private writer schemas are outside its enforced list. |

is_mesh_member EXECUTE is granted to authenticated/postgres; PUBLIC EXECUTE is
present on the two trigger-returning helpers. Trigger/event-trigger functions
cannot be used as ordinary scalar RPCs merely because EXECUTE is granted; this
is not evidence of an authentication bypass. Keep privilege minimization under
review, without rewriting helper logic or managed relationships speculatively.

Custom event trigger ensure_rls is enabled in origin mode, on ddl_command_end,
with the three tags above and handler rls_auto_enable(). Other exported event
triggers are supabase_admin-managed; preserve the TEST project's native versions
rather than copying production-managed DDL. The private-principals auto-RLS concern
in older proposals is not supported by this captured public-only handler. Check
actual TEST behavior in case its native handler differs.

No embedded credential was apparent in the three reviewed helper bodies. This is
not a general guarantee about every arbitrary SQL literal or future export.

### Sequence precision limitation

The identity sequence is postgres-owned bigint, internal dependency on
security_incidents.incident_number; start/increment/min/cache are 1 and cycle is
false. However, the JSON's seqmax is `9223372036854776000`, outside signed bigint
range (maximum `9223372036854775807`). The Python JSON parser retains that literal;
rounding apparently occurred before this file was read, possibly during export.
Do not replay that impossible maximum or claim it is an exact production value.

For a TEST-only identity sequence, using PostgreSQL's normal ascending bigint
maximum is an explicit reconstruction choice. Document it as a fidelity exception,
not a production setting verified from this damaged field. No additional production
inspection is needed to proceed with a non-identical functional test fixture.

## Can TEST reconstruction replace missing original scripts?

**Yes for a reviewed disposable functional fixture; no for an identical clone,
production baseline migration or proof of production data validity.** The originals
are no longer a hard prerequisite to TEST preparation now that helper bodies exist.

Offline reconstruction design (now prepared in the TEST package, not executed):

1. Use the older 18-table metadata and two enum definitions for dependency ordering,
   types, defaults, constraints/indexes and existing policy/grant definitions.
2. Prefer all 18 empty application table definitions. A ten-table minimum closure
   is sufficient only after verifying actual helper/FK dependencies; the recovered
   membership/profile helpers reference the foundation tables already included.
3. Restore only public custom helper definitions, reviewed owners/EXECUTE ACLs,
   defaults and safety settings. Preserve their existing semantics; no always-true
   helper stubs or guessed owner overrides. Recreate the public Auth provisioning
   trigger against the TEST project's existing auth.users, never clone Auth rows.
4. Build security_incidents.incident_number as GENERATED ALWAYS identity with the
   verified sequence name/type/options, recording the maximum-value exception.
5. Reproduce application RLS flags/policies/grants and reviewed creator defaults.
   Record the TEST project's managed-role graph and compare it, rather than
   replaying global role grants/attributes or supabase_admin-owned event triggers.
6. Review ensure_rls setup/permissions in the new project. If an equivalent native
   trigger exists, verify it; if registration is prohibited, explicitly enable RLS
   on fixture tables and mark automatic-DDL behavior untested. Do not bypass that
   platform restriction by using production credentials.
7. Keep fixture SQL outside migrations/, label it TEST-ONLY/not production-identical,
   record source hashes and every intentional deviation, then inspect its catalog
   in TEST before testing either proposal. No production values/rows are needed.

Not exactly recoverable/proven: original script ordering/comments/transaction
history, the damaged sequence maximum/current counter, uninspected table storage/
physical options, dynamic dependencies not captured by catalogs, managed-platform
configuration/role equivalence, extension version parity and actual row-level
duplicate/orphan/volume characteristics. The two captures are from different
times; the compared five-table definitions agree but this is not one complete
atomic 18-table snapshot. Treat absence of data as intentional, not as a clone.

## Production isolation review

The plan DOES reference the production project as an explicit excluded/denied
identifier. It does not use that reference as a connection destination. Its test
wrapper rejects that reference, constructs the pooler username using a separately
entered TEST reference, requires port 5432/TLS verification, and stages test files
outside the repository. No executable --linked command appears in the plan.

The local Supabase CLI link remains production, so do not invoke linked CLI
operations or relink the repository. No commands from the execution/fixture/
migration sections of DISPOSABLE_TEST_PLAN.md were run during Stage 1.

Before any later connection, recheck the explicit TEST project reference, host and
pooler username together. Use a fresh terminal and clear stale PGHOSTADDR as well
as PGSERVICE/PGSERVICEFILE/PGPASSWORD so inherited libpq routing cannot surprise
the operator. Do not rely on current_database() alone: both projects use postgres.
No passwords, tokens, service keys or full connection strings belong in reports.

## Separate Free test project: exact configuration steps

These steps are prepared for later use, NOT executed by this review. Review
the proposed TEST reconstruction before consuming a project slot. Project creation
does not authorize any schema load or either migration.

1. Open Supabase Dashboard and select an organization explicitly labeled Free.
   Confirm an unused Free-project slot. Current documentation lists two active
   Free projects and 500 MB database size per project. If none is available, stop;
   do not pause/delete MESH, upgrade or create a paid project/branch.
2. Choose New project, name it mesh-vader-disposable, and select the intended
   region (prefer production's region when available without extra cost).
   Generate a distinct database password and save it only in a password manager.
   Confirm Free before creating. No production cloning, data import or integrations.
3. Record the new project reference from its dashboard URL/settings. It must
   differ from khweikfvsnervfuswhon. Do not paste a credential-bearing connection
   URI into chat or a tracked file.
4. In the TEST project's Connect panel, select the Shared Pooler / Session mode
   on port 5432. Record only hostname, port, database postgres and the username
   postgres.TEST_PROJECT_REF. Obtain TLS certificate/verification instructions
   for that project and retain the CA certificate locally.
5. Use no paid IPv4 add-on, dedicated pooler, PITR, branching, custom domain or
   deployed function. Shared session pooling supports IPv4. Do not use HTTP RPC
   as a substitute for custom-login testing later.
6. Confirm PostgreSQL major 17 via project metadata if exposed. If it is not
   visible, leave it unverified until a separately confirmed read-only TEST
   connection; the proposal guards require major 17. Do not weaken them.
7. Stop. Return only the non-secret TEST reference, Free status, region and selected
   connection mode. Do not load schemas, create test users/roles or execute the
   migration wrappers until Stage 2 confirmation.

Windows client setup prerequisite: use the official PostgreSQL Windows installer
and select Command Line Tools (including psql), with server/pgAdmin/StackBuilder
unchecked if unnecessary. No Docker, WSL or local database server is needed.
No installer was downloaded or run here. After installation, verify locally:

```powershell
Get-Command psql.exe -ErrorAction SilentlyContinue
psql.exe --version
```

If only an absolute executable path is available, use its actual installation
path for --version and a session-local PATH adjustment; don't assume versioned
folders exist. `--version` does not connect to any database.

Sources checked:
[Supabase Free limits](https://supabase.com/kb/faqs/platform/database-only-cost),
[pooler/custom-role connection setup](https://supabase.com/docs/guides/database/connecting-to-postgres),
[official Windows downloads](https://www.postgresql.org/download/windows/),
[EDB Command Line Tools component](https://www.enterprisedb.com/docs/supported-open-source/postgresql/installing/windows).

## Missing prerequisites and exact next action

Resolved: consolidated verification export, all three helper bodies/defaults/
safety settings, helper ACLs, managed membership evidence, event-trigger registration
and identity sequence metadata (with the explicit precision exception).

Remaining prerequisites:

1. Prepared TEST package must pass its first read-only remote preflight before any
   mutating bootstrap approval. Source hashes, application schema correspondence,
   SQL delimiter checks and PowerShell parsing pass locally; PostgreSQL compilation
   is not tested. Originals are no longer a hard TEST-fixture requirement.
2. Client installation is resolved: explicit psql path reports 18.6. No installer
   was run by the agent. Runtime TEST authentication is not yet attempted.
3. Confirm the user-created TEST project's Free plan, PostgreSQL 17 server,
   explicit TEST host/user, TLS CA and session-pooler settings.
4. Confirm hosted custom-login/ownership-transfer capabilities and actual tenant
   isolation in TEST. Catalog flags do not establish those runtime behaviors.
5. Check native helper/event-trigger compatibility and permission to reuse/create
   the captured ensure_rls event trigger; failures abort rather than skip coverage.
6. Synthetic tenants are in a separate optional seed file; full writer fixtures
   remain later work. Confirm SQL execution separately before any schema loading,
   proposal application, seeding or runtime test execution.

**Next manual action:** obtain the hostname and TLS CA from TEST project
ikmzxirldivefebgxzaa's Connect panel. After explicit read-only execution approval,
use the prepared launcher's ConnectionCheck action and review its JSON. Do not
run Bootstrap or either migration as an automatic follow-up. See the TEST package
README for exact psql 18.6 commands and all fidelity exceptions.
