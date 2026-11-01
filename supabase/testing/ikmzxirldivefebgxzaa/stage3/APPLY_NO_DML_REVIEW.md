# Migration 01 TEST Apply without DML probes

Status: prepared and locally reviewed only. **GO for explicit authorization of
one guarded TEST attempt and its read-only verification; execution NOT RUN.**
Production `khweikfvsnervfuswhon`, Migration 02, DML/RLS tests, deployment and
commit/push remain excluded. Earlier approval of a different Apply procedure is
not authorization to execute this new variant.

## Exact SQL difference

New file: `apply_no_dml.sql`. It is byte-for-byte equal to reviewed `apply.sql`
after removing exactly its TWO complete `\ir dml_probes.sql` lines:

1. The include after `assert_baseline.sql`, before the approval GUC.
2. The include after `assert_hardened.sql`, before pre-COMMIT evidence output.

No added SQL, reordered statements, changed guards, relaxed checks or migration
edits. Original `apply.sql`, `pins.json`, launcher, proposal, baseline, gate,
rollback, verification and saved evidence remain unchanged.

SHA-256 of original Apply (unchanged):
`7b942e61d759fa3b7696a1c8b13a3e86d290967fffa5c05ca728e3c185d6a64b`

SHA-256 of new Apply:
`5629a6d37d66a0ceb6034ef5d3f4bcb8afdec3292dc1770eb790137a74d30c86`

SHA-256 of unchanged Migration 01 proposal:
`1aefa726f675f3b5441495e033262442355337f528933512376b40fe9cdb55bd`

`pins_no_dml.json` records hashes of the separate launcher, both offline utilities,
all original reviewed artifacts, the variant and prior successful evidence. The
launcher checks these pins before any connection or attempt reservation. Both
pin manifests remain separate. Do NOT run the original `build_stage3.py` to
update this package: it scans the directory and would rewrite original pins.

## Assertion and dependency review

The removed DO-based probes use only local variables and transaction-local role
switches, returning no inputs used by subsequent scripts. All snapshots, approval
GUCs and pre-COMMIT evidence are set independently by the retained Apply. Thus
removing the probes invalidates no assertion or dependency. It removes actual
zero-row DML execution coverage, not any catalog-based security assertion.

Retained unchanged: one BEGIN/COMMIT, lock/statement timeouts, short exclusive
target-table locks, TEST identity/operator/version/inventory checks, exact saved
baseline digest, no-column-ACL checks, original Migration 01 body, effective
inherited-rights assertions, legitimate-rights equality, native-object equality,
fail-fast psql handling and explicit post-COMMIT acknowledgement.

The complete Apply include closure is:

| File | Executed behavior |
|---|---|
| apply_no_dml.sql | Transaction, locks, snapshots/approval settings, evidence and COMMIT |
| guard.sql | Fail-fast; approval/operator/version/ownership/RLS checks |
| ../target_guard.psql | Fixed TEST client-route checks |
| snapshot.sql | Catalog SELECTs only; no application/Auth records |
| assert_baseline.sql | Catalog/JSON assertions; exceptions on drift |
| migration01_body.sql | Unchanged proposal gate, baseline assertions, targeted REVOKEs and residual-right audit |
| assert_hardened.sql | Inherited dangerous/frontend rights, unchanged legitimate permissions and native-state assertions |

The Verify closure is only verify.sql, guard.sql, target_guard.psql, snapshot.sql
and assert_hardened.sql. It runs BEGIN READ ONLY and ends ROLLBACK. No included
path reaches dml_probes.sql, dml.sql, rls.sql, Migration 02, fixtures or bootstrap.
REVOKE INSERT/UPDATE/DELETE are permission statements, not data writes.

New launcher `Invoke-Migration01NoDml.ps1` does not call the old launcher and only
accepts Validate, ApplyNoDml or VerifyNoDml. There is no arbitrary SQL path or DML,
RLS, bootstrap, role-provisioning or writer action. Reading/hashing old scripts
and rollback evidence does not execute those scripts or their earlier DML probes.

## Connection and one-attempt protections

Fixed TEST route: aws-0-eu-west-1.pooler.supabase.com:5432, postgres database,
postgres.ikmzxirldivefebgxzaa username. TLS remains verify-full with the reviewed
CA byte hash, CA constraints/validity checks, and no client private key. Inherited
libpq credentials/routes/options are cleared and restored. Password entry uses
psql -W in the operator's own terminal; passwords never enter arguments or files.
Project attribution remains the verified dashboard route, exact TEST pooler user
and TLS, rather than an independent server project-reference setting.

The new launcher requires successful baseline/gate/rollback receipts with unchanged
hashes. Local review reconfirmed exact baseline/restoration snapshot equality.
It refuses evidence of any original Apply attempt, preventing execution when an
earlier committed/unknown outcome needs resolution. It reserves each new phase's
receipt using CreateNew, refuses existing files, and never retries or deletes an
attempt marker. New evidence filenames cannot overwrite the previous results:

- evidence/apply_no_dml.txt and apply_no_dml.receipt.json
- evidence/verify_no_dml.txt and verify_no_dml.receipt.json

Verify requires a successful receipt for this exact variant and compares its
fresh catalog snapshot with Apply's asserted pre-COMMIT `after` snapshot. It does
not use the original launcher's apply receipt. No next action runs automatically.

## Execution plan — do not run without new explicit authorization

Local-only validation, already performed:

```powershell
$noDmlRunner = 'C:\Users\APOORV\OneDrive\Desktop\MESH\meshcode\Mesh\supabase\testing\ikmzxirldivefebgxzaa\stage3\Invoke-Migration01NoDml.ps1'
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File $noDmlRunner -Action Validate
```

After explicit approval of this variant, run ONE Apply in your own terminal:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File $noDmlRunner -Action ApplyNoDml -ApproveNoDml
```

Only after PASS and acknowledged COMMIT, and if read-only follow-up is authorized:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File $noDmlRunner -Action VerifyNoDml -ApproveNoDml
```

Each database phase prompts for the TEST password. Stop on any unexpected error.
Any SQL error before COMMIT rolls back when the client disconnects. Lost COMMIT
acknowledgement is UNKNOWN, not a confirmed rollback: retain receipts, do not
retry, and request a separately approved read-only inspection. Verify failure
cannot undo a prior COMMIT; do not automatically restore dangerous grants.

Expected PASS: no effective TRUNCATE/REFERENCES/TRIGGER/MAINTAIN on the five tables
for anon, authenticated, authenticator or service_role; no frontend I/U/D;
all other effective privileges unchanged; RLS, policies, schema objects, helper
definitions/settings/ACLs, managed roles/memberships/native ACLs unchanged; fresh
read-only snapshot equal to the asserted post-state. The original creator-wide
default ACL risks remain unchanged; this proposal does not fix future objects.

## Validation evidence and limits

PASS: original pin manifest still validates; variant equals EXACT two-line
removal; full recursive include closures reviewed; existing baseline/gate/rollback
receipts and output hashes valid; exact rollback restoration; new launcher pins
validate in local-only mode; PowerShell syntax parser and Python checks pass.
No existing receipt was overwritten and no new execution receipt was created.

No PostgreSQL execution, database connection, DML/RLS probe or migration occurred
during preparation. PostgreSQL parser is not installed locally. Runtime behavior
of this variant and post-COMMIT verification remain untested. Earlier rollback
evidence supports the unchanged migration body, but does not replace the future
variant's execution evidence. Strict native snapshot drift still aborts; do not
relax that check to bypass unrelated managed background changes.

**GO for review and explicit TEST execution authorization. NO-GO for executing
now, production, Migration 02, or DML/RLS tests under this review.**
