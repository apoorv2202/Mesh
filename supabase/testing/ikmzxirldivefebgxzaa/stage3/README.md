# Stage 3: guarded Migration 01 runtime tests

PREPARATION ONLY. Nothing in this package has been executed against PostgreSQL.
Explicit user authorization is required before **any** database phase. TEST is
`ikmzxirldivefebgxzaa`; production `khweikfvsnervfuswhon` is strictly excluded.
Migration 02, linked Supabase commands, relinking, deployment and commit/push are
outside this procedure. Do not rerun the bootstrap.

## Reviewed starting point and scope

The successful bootstrap execution record and all 12 post-bootstrap inspection
sections were reviewed. They contain 18 application tables, 165 columns, 85
constraints, 46 indexes, 18 policies, two enums and three helpers. The five
persistence tables contain 57 columns, 31 constraints and 15 indexes. No schema
or migration proposal has been modified by Stage 3 preparation.

`FINAL_REVIEW.md` and older parts of `DISPOSABLE_TEST_PLAN.md` describe earlier
missing inputs. The current exported helper definitions and successful bootstrap
supersede those historical prerequisites. Their production NO-GO and remaining
runtime requirements remain valid. In particular, **do not follow the older
inherited-failure example granting a synthetic parent role to anon**: changing
managed memberships is prohibited in this stage.

## Files and guards

- `Invoke-Migration01Test.ps1`: fixed TEST route, project-specific pooler user,
  verify-full TLS with pinned CA, interactive `psql -W`, `-X`, environment cleanup,
  explicit named phase and approval switch. Defaults to local validation only.
- `pins.json`: hashes of SQL, launcher, offline utilities, target guard and exact
  unchanged proposal. Regenerating pins is preparation requiring renewed review,
  never an automatic response to a failed execution guard.
- `build_stage3.py`: offline derivation of the proposal body. Removes only its
  outer BEGIN/COMMIT so the harness owns ONE transaction; all proposal guards,
  revocations and assertions remain. Never nest the original proposal transaction.
- `snapshot.sql`: effective 5-role × 5-table × 8-privilege matrix, target and column
  ACLs, all role attributes/membership edges, schema ACLs, function ownership/ACLs
  and settings/body hashes, native event triggers, defaults, non-target relation
  ACLs, sequence definitions, policies, constraints, indexes and trigger hashes.
  No application rows, Auth user records, password hashes or function bodies.
- `baseline.sql`: read-only metadata baseline. Requires all **60** dangerous rights
  (3 API roles × 5 tables × 4 privileges) true and no target column ACLs.
  Authenticator and postgres are captured even where their effective rights differ.
- `gate.sql`: tests the exact extracted proposal approval gate with approval OFF;
  requires its precise P0001 error and unchanged metadata, then rolls back.
- `rollback.sql`: runs the actual reviewed body, tests hardened rights and 100
  zero-row DML probes, then raises the exact deliberate P0001 exception. Only this
  statement tolerates an error. Rolls back to a pre-migration savepoint and requires
  FULL baseline JSON equality, including original ACL representation, inherited
  effective rights, managed objects and policies. Ends with outer ROLLBACK.
- `apply.sql`: same body/assertions with COMMIT, no intentional failure. Exact
  baseline digest must still match before changes. Takes short ACCESS EXCLUSIVE
  locks on the five tables; use an idle disposable environment. A timeout is FAIL,
  not permission to increase locks or terminate other sessions automatically.
- `assert_hardened.sql`: denies the four dangerous privileges to anon,
  authenticated, authenticator and service_role including effective inherited,
  PUBLIC and ownership paths. Denies frontend I/U/D; all remaining rights, including
  postgres administrative access and existing SELECT/service-role DML, must remain
  exactly as before. All native snapshots, column ACLs and RLS/policies unchanged.
- `verify.sql`: fresh READ ONLY connection; repeats effective-rights assertions.
  Launcher also compares its full result with apply's pre-COMMIT snapshot.
- `dml.sql` / `dml_probes.sql`: actual zero-row SELECT/INSERT/UPDATE/DELETE checks
  under SET LOCAL ROLE for all five roles/tables, matching effective ACLs (100
  probes). No rows read or changed; end in rollback. They also run before/after
  migration within rollback/apply. These need read-write transactions because
  PostgreSQL rejects INSERT syntax even with zero rows in READ ONLY mode.
- `rls.sql`: separately approved rollback-only synthetic policy tests described below.
- `validate_stage3.py`: local integrity/structure checks, not a PostgreSQL compiler.

The route is fixed to `aws-0-eu-west-1.pooler.supabase.com:5432`, database postgres,
user `postgres.ikmzxirldivefebgxzaa`, with the reviewed downloaded CA. The server
does not expose an independent project-reference setting; identity still depends
on the dashboard-confirmed route, TEST-specific username and verified TLS. Never
copy these SQL fragments into an arbitrary connection or SQL Editor.

Each phase reserves its receipt once in `evidence/`. Existing receipts or output
files prevent re-execution/overwrite. Gate/rollback/apply dependencies require
successful receipts, unchanged output hashes and the same proposal. Every phase
stops on failure, with no automatic next phase or retry. Do not delete failed
receipts to bypass this rule. Passwords are never arguments, variables or files.

## Exact execution sequence — AFTER explicit authorization

Open your own PowerShell terminal; do not send passwords in chat. Set only this
nonsecret script path:

```powershell
$stage3Runner = 'C:\Users\APOORV\OneDrive\Desktop\MESH\meshcode\Mesh\supabase\testing\ikmzxirldivefebgxzaa\stage3\Invoke-Migration01Test.ps1'
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File $stage3Runner -Action Validate
```

After authorization, execute ONE line at a time. Inspect its PASS/result before
the next line. Each database phase prompts for the TEST password. No transcript
or terminal recording that might capture manual credentials should be enabled.

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File $stage3Runner -Action Baseline -ApproveStage3
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File $stage3Runner -Action Gate -ApproveStage3
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File $stage3Runner -Action Rollback -ApproveStage3
```

Expected rollback output includes `VADER_STAGE3_INTENTIONAL_ABORT` (P0001), then
JSON `restored: true` and PASS. That ONE error is expected. Any earlier revocation,
assertion, permission error, different error code or connection error is FAIL.
Review `baseline.txt`, `gate.txt`, `rollback.txt` and their receipts before authorizing
the committed phase if approval was limited to rollback testing.

Only when authorization explicitly includes committed TEST execution:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File $stage3Runner -Action Apply -ApproveStage3
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File $stage3Runner -Action Verify -ApproveStage3
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File $stage3Runner -Action Dml -ApproveStage3
```

Apply requires `MIGRATION01_COMMIT_ACKNOWLEDGED` after COMMIT. Pre-COMMIT evidence
alone is not commit proof. Verify requires exact post-commit catalog equality.
All assertions run BEFORE COMMIT, and any ordinary error disconnects/rolls back.
A failed Verify cannot roll back an already successful Apply; stop and investigate.

## Legitimate access and RLS coverage

The captured baseline grants **no table SELECT/I/U/D to the API roles**. Therefore
denial of those operations is expected, including service_role despite BYPASSRLS.
Migration 01 introduces no read grant or writer access. Do not grant frontend
writes to turn a denied probe into success. The postgres zero-row positive probes
confirm preserved administrative rights; they do not prove an application writer.
Real permitted persistence operations belong to Migration 02 and remain untested.

Policy behavior needs a temporary SELECT grant to authenticated to distinguish
RLS from the existing ACL denial. `rls.sql` grants ONLY SELECT on security_events
inside a rollback-only fixture transaction; never changes RLS or policy bodies.

Prerequisite: two distinct, NEW synthetic TEST Auth users created separately via
the TEST dashboard, with creation explicitly authorized. Record only their UUIDs;
never credentials or emails in repository evidence. No provisioning is performed
by these scripts. The omitted Auth provisioning trigger means new users should
have no existing public.profiles rows. A conflict or missing Auth FK is FAIL;
do not delete users/profiles to make the test pass.

The launcher validates UUIDs and accepts them as `-UserA` / `-UserB`:

```powershell
# Assign the two nonsecret synthetic TEST UUIDs in your terminal before this line.
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File $stage3Runner -Action Rls -ApproveStage3 -UserA $stage3UserA -UserB $stage3UserB
```

Fixture creates two organizations, profiles, active security-team memberships and
one event per organization, all transaction-local. A sees A only, B sees B only;
suspended B and an outsider see neither. Savepoint rollback removes every fixture
row and SELECT grant; full metadata equality is asserted before outer rollback.
Use the reserved UUIDs/source namespace only in the otherwise idle TEST project.
This is SQL role/JWT impersonation and one representative event policy, **not**
real JWT authentication, all-18-policy coverage, positive writer tests or custom
database LOGIN proof. Missing synthetic users means RLS is BLOCKED, not passed.

## PASS / FAIL and recovery

| Phase | PASS | FAIL / response |
|---|---|---|
| Baseline | Correct identity/inventory; 60 dangerous rights; complete 200-cell matrix; no column ACL | Drift/missing role/right: stop before changes |
| Gate | Exact closed-gate P0001; full metadata unchanged | Any other error or no error: stop |
| Rollback | Hardened assertions pass, intended abort, exact baseline restored | No restoration proof: stop; no Apply |
| Apply | Precommit native/legitimate rights unchanged; forbidden effective rights false; COMMIT acknowledged | SQL error: disconnected transaction rolls back; lost acknowledgement: outcome UNKNOWN |
| Verify | Fresh connection matches entire asserted post-state; inherited rights absent | Stop further tests; do not auto-restore grants |
| DML | 100 actual zero-row role checks match ACLs | Unexpected permission/result: stop |
| RLS | A/B isolation and suspended/outsider denial; fixture/grant rolled back | Missing users is blocked; leakage or restoration error is fail |

No managed-role inheritance is removed. If an existing parent grants residual
rights, the transaction fails closed. Intentionally injecting an inherited-right
failure by altering Supabase memberships is excluded. Such a fault-injection case
needs separately reviewed disposable role/schema design; it is not claimed tested.

On failure keep every receipt/output and terminal SQLSTATE (never passwords).
Before COMMIT, closing psql rolls back pending work; savepoint recovery handles
only the deliberate abort. For a network interruption near COMMIT, treat state as
unknown, do not retry Apply. Request a new approved READ ONLY inspection through
the same route first. Read-only verification has its own one-phase guard; do not
delete its receipt to force a retry.

After a confirmed commit, regranting dangerous rights is NOT automatic recovery.
Baseline ACLs and native snapshots are retained for a separately reviewed,
TEST-only restoration proposal if necessary. Do not use GRANT ALL, membership
changes, disable RLS, reset, drop/rebootstrap or touch production. No recovery SQL
is executed by this harness. Stop if unrelated managed background catalog changes
cause strict snapshot mismatch; review drift rather than relaxing preservation.

Return all phase receipts and metadata outputs for review; no raw helper bodies,
Auth records or credential values. Successful Stage 3 tests would establish only
disposable Migration 01 behavior. Future-object default ACL risks, production
catalog/data drift, production migration-history reconciliation and every
Migration 02 runtime gate remain unresolved.

## Current decision

GO for review/authorization of this prepared TEST procedure; runtime status is
**NOT RUN**. No production approval. No PostgreSQL execution occurred during
preparation. Static checks cover pin integrity, exact proposal body derivation,
include resolution, transaction/gate ordering, lexical structure and PowerShell /
Python parsing. They cannot prove PostgreSQL compilation or runtime behavior.
