# VADER Phase 2 final migration review

Review date: 2026-10-29. **Neither proposal is approved for production application.**
No SQL was executed remotely and no database permissions were changed.

## Evidence boundary

The saved mesh_inspection.json supplies the exact five-table definitions: 57
columns, 31 constraints, 15 indexes, postgres ownership and enabled RLS. The user
now confirms the successful consolidated verification found effective TRUNCATE,
TRIGGER, REFERENCES and MAINTAIN for anon/authenticated/service_role, zero column
ACL entries, active-membership/auth.uid behavior in is_mesh_member, and the
postgres-owned incident identity sequence. These confirmations are accepted.

The consolidated result JSON itself is not present in the inspection directory
at review time. Consequently this review cannot independently quote its role
inheritance paths, helper settings, owner memberships or event-trigger scope.
It does not claim those unreported details were verified. Custom-login
connectivity and runtime isolation are explicitly untested.

## Necessary local revisions

01 keeps its targeted table-level revocations and fail-closed residual privilege
audit. Added preflight asserts the reviewed PostgreSQL 17 version, three expected
API roles, five postgres-owned RLS base tables and absence of column ACL entries.
This prevents missing objects from making loops vacuously pass and stops if the
verified no-column-grants assumption drifts. Changed the read-grant comment to
acknowledge confirmed helper membership semantics; no frontend SELECT or writes
were newly granted.

02 retains the same role/function/tenant design. Added preflight checks for the
five reviewed tables/API roles, exact postgres-owned identity sequence and ALWAYS
identity column, required extension signatures, completed effective dangerous-
privilege cleanup, and no effective frontend column/table write path. It aborts
if 01 is skipped or its desired outcome is not achieved. No login provisioning,
managed-role membership changes, extra persistence fields or new API scope were
introduced by this review.

## Security-hardening proposal 01

**Design decision: GO for disposable-database validation.**
**Production application decision: NO-GO until the following gates pass.**

1. A disposable PostgreSQL 17/Supabase-equivalent test must successfully apply
   the guarded transaction under the intended deployment identity and show all
   four dangerous privileges false afterwards for all three API roles.
2. Confirm whether rights come only from the directly revoked grantees/PUBLIC.
   If a parent role, table ownership or elevated role preserves a right, the
   postflight aborts the whole migration. Review a specific grant-provenance fix;
   do not alter managed memberships merely to make the assertion pass.
3. Demonstrate guard failure, residual-privilege failure and rollback leave
   preexisting ACLs intact. Validate no supported application operation depends
   on the four revoked privileges and capture original ACLs for controlled recovery.
4. Reconfirm baseline/absence of drift at application time and obtain explicit
   approval to execute. Empty remote migration history is still a separate
   migration-process concern; do not db-push these proposals.

No custom login, tenant helper behavior or writer migration is necessary to
perform this targeted cleanup. They do not block validating 01 independently.
The migration revokes privileges on exactly the five tables, changes no role
attributes or memberships, retains RLS/policies/table ownership, and grants no
API writes. API role membership in service_role through authenticator may be
part of Supabase operation; it is not automatically a relationship to remove.

Global/creator-specific default ACL changes remain excluded because they affect
future objects across MESH. That leaves a documented future-object regression
risk, not a reason to grant ALL or rewrite managed-role relationships. A migration
pipeline ACL check is required for future tables.

## Transactional writer proposal 02

**Design decision: suitable for disposable compilation/provisioning tests only.**
**Production application decision: NO-GO. Exact unresolved gates follow.**

| Area | Static review result | Blocking proof still needed |
| --- | --- | --- |
| SECURITY DEFINER search_path | All three definer entry/scope functions explicitly use pg_catalog,pg_temp; application/private objects and extension functions are schema-qualified | Compile under PostgreSQL 17 and test hostile search_path/temp objects; privately verify existing definer/event-trigger settings |
| EXECUTE surface | PUBLIC/anon/authenticated/service_role revoked on entry functions; only vader_ingest granted entry EXECUTE; private helper execution revoked from callers | Check actual resulting ACLs and inherited execution paths, including creator-specific defaults |
| Function owner | New NOLOGIN/NOBYPASSRLS non-superuser owns functions, not application tables; only scoped SELECT/INSERT table access | Managed deployment identity must be allowed to CREATE ROLE and SET/transfer ownership to that role. CREATEROLE alone is not a successful ownership-transfer test |
| Schema rights | USAGE separated from temporary CREATE for ownership transfer; CREATE revoked before commit | Test ownership transfer, no surviving caller/owner schema CREATE, and no PostgREST exposure |
| Tenant binding | Database session_user maps OID+name to one enabled organization; payloads cannot select another tenant; extra role memberships rejected | Authenticate two actual custom tenant logins through intended backend endpoint; test role recreation, disabled mapping and SET ROLE paths |
| RLS | Writer is not table owner/BYPASSRLS; new SELECT/INSERT policies check bound organization, including receipts | Real A/B/unmapped sessions must show read/write isolation; test private-principals behavior if rls_auto_enable also enables RLS there |
| Incident numbering | Existing verified ALWAYS identity omitted from INSERT; only sequence USAGE granted to function owner | Actual identity insert and sequence privilege behavior under restricted owner; ownership alone does not prove grant authority |
| Parent references | Existing composite tenant FKs retained; generated finding/incident subject FKs add database enforcement for risks | Validate existing subject references and test foreign/nonexistent IDs, updates and parent deletes; asset/identity scores remain outside writer scope |
| Atomicity | Application inserts, links and replay receipts use one function/outer transaction; errors rethrown, no internal COMMIT | Fault injection after every write stage and before outer COMMIT; unknown-commit retries and rollback tests |
| Concurrency | Tenant transaction lock plus history revision check | Concurrent workers, autocommit misuse, connection/transaction pinning, stale-history retries and bounded late-arrival tests |
| Idempotency | Server-derived UUIDv5 keys plus immutable payload equality and stored receipts; triage not overwritten | Cross-language identity vectors/planning interface, replay/conflict tests, and legacy-row overlap assessment |
| Existing data/DDL | New FKs validate rather than silently accepting legacy violations | Authorized orphan assessment, table rewrite/lock budget, capacity, backup and rollback rehearsal; metadata does not establish row validity |

Custom-role connections are supported in Supabase generally; their availability
for this project's chosen endpoint/runtime is not proven by SQL Editor access.
The proposal intentionally rejects postgres/authenticator sessions and cannot be
used unchanged as a Supabase SDK/PostgREST RPC. Do not weaken session_user checks
or substitute a caller-controlled organization GUC to make it work.

If the direct-login requirement cannot be met, stop 02 and separately review a
single-transaction RPC design whose machine identity is verified and mapped to
tenant server-side/database-side, with safe execution grants and atomic history
revision validation. A service-role key plus an arbitrary tenant parameter is
not an equivalent tenant boundary. No fallback implementation was added here.

## Disposable test requirements and unchanged scope

Use an explicitly disposable PostgreSQL 17 or Supabase test project with synthetic
tenants and the reviewed real helper definitions/roles; avoid production data.
The detailed tests/rollback sequence in README.md still apply. Minimum release
evidence: SQL/function compilation; migration-guard and rollback behavior; no
effective dangerous API rights; successful least-privilege ownership/sequence
setup; two real-login tenant isolation; risk FK enforcement; concurrent retry/
partial-failure tests; identity canonicalization and privilege/search_path attacks.

The confirmed is_mesh_member semantics remove uncertainty about its high-level
active-member/auth.uid logic only. They do not prove search_path safety, all NULL/
role override cases, or the separate handle_new_mesh_user/rls_auto_enable bodies.
No new authenticated SELECT grant is justified by this summary alone.

Static checks on the revised proposals pass delimiter/transaction structure,
review guards and application INSERT-column correspondence with the saved schema.
They are not PostgreSQL/PLpgSQL parsing or execution. No disposable environment was
available or exercised in this review. Phase 1 Python tests were not rerun because
no Python files changed; their prior 38-pass result does not validate database SQL.

Both production decisions remain NO-GO. Next stage is approval/provisioning of a
disposable environment and testing 01 independently before evaluating 02 there.
This review grants no permission to apply either proposal remotely.
