# Stage4 harness revision 2: temporary namespaces and fail-fast evidence

Prepared 2026-10-30, Asia/Calcutta. No database connection, SQL execution, fixture,
Stage4 runtime test, migration, production access, deployment or commit/push.

**GO for review and a fresh SELECT-only TEST preflight. NO-GO for runtime until
that preflight passes and explicit revision-2 execution authorization is given.**

## Diagnosed cause and unchanged trust anchor

The diagnostic actual hash b078d1503de80cbbcdea96bdeeb36ebc differed only by 20
namespace rows. The user verified all were other-session temporary namespaces:
ten pg_temp_* and ten pg_toast_temp_*, all supabase_admin-owned, with no relations.
All other captured categories were identical. Fixtures were absent.

Trusted post-M01 baseline stays byte-for-byte unchanged, MD5:
`90a71db3b16ed177b3455f61a59343b2`.
The original stage3/snapshot.sql is also unchanged. Its complete raw snapshot is
still captured. No baseline replacement, new accepted database state, weakened
grant/policy check, role change or blanket pg_* exclusion was introduced.

## Exact changes to existing files

| File | Reviewed change |
|---|---|
| stage4/runtime.sql | Normalize only temporary namespace rows before the same baseline MD5 comparison; diagnostics before assertions; normalized before/after restoration comparison; remove invalid quit branch |
| stage4/guard.sql | Missing/rejected approval emits a failure record and raises 42501 under ON_ERROR_STOP |
| stage4/cleanup_check.sql | Same normalized metadata comparison and diagnostics in the read-only cleanup connection; no invalid quit |
| target_guard.psql | Missing/wrong TEST route emits a failure record then raises 42501; route conditions unchanged |
| stage4/Invoke-Stage4.ps1 | Revision-2 pins and evidence_r2 directory; pure result parser; nonzero exit takes precedence; verbose PostgreSQL SQLSTATE on original stderr; explicit failure receipt; preservation remains unverified on failure |
| stage4/validate_stage4.py | Revision-2 integrity/fail-fast/include assertions |
| stage4/pins.json | Only six allowlisted existing script hashes updated; new helper/test/preflight/history hashes added; revision set to 2 |
| stage4/STAGE4_TEST_PLAN.md | Revision-2 notice and authority link; test scope unchanged |

## New files

- capture_comparison.sql: original raw capture plus narrow schema normalization,
  expected/raw/comparison hashes, excluded temporary namespace inventory, full
  raw snapshot and target column diagnostics.
- assert_comparison.sql: same expected MD5 assertion; structured mismatch evidence
  followed by SQL exception P0001, never a silent or successful early quit.
- Stage4-Results.ps1: local evidence parser, no database invocation.
- Test-Stage4Offline.ps1: synthetic success/failure evidence tests, no launcher.
- test_harness_r2.py: offline normalization, persistent-security regression and
  baseline/historical evidence integrity tests.
- prepare_preflight_r2.py / preflight_r2_read_only.sql: independent SELECT-only
  preparation/capture for validating the correction before another runtime.
- review_harness_r2.py: one-time allowlisted pin review utility, already run.
- review_history/pins_before_r2.json: exact previous pin manifest preserved.
- HARNESS_R2_REVIEW.md: this review and execution gate.

## Temporary schema handling

Normalization changes ONLY raw snapshot native.schemas. A row is excluded only
when its live catalog namespace satisfies BOTH:

1. Exact PostgreSQL temporary namespace shape
   `^pg_(temp|toast_temp)_[0-9]+$`.
2. PostgreSQL identifies it as another session's temporary namespace, OR it is
   pg_my_temp_schema(), OR its name is the exact toast companion of that current
   temporary schema (suffix resolved from the actual pg_my_temp_schema row).

This does not trust a name alone, does not whitelist the previously observed 20
OIDs, and does not ignore all schemas owned by supabase_admin. Persistent public,
auth, extensions, pg_catalog, pg_toast and every other persistent namespace remain
in the original ordered OID/owner/ACL comparison. Added/dropped persistent schemas
and persistent ownership/ACL changes still change the digest and abort.

The original schemas row shape and array order are preserved. Every other raw
snapshot field is unchanged. Temporary relations, routines, ACLs, constraints,
indexes and triggers are NOT broadly excluded from other captured categories;
their drift remains subject to original checks. Ignored namespace rows and raw
hash/snapshot are retained for audit, rather than hidden or discarded.

The trusted baseline contains the reviewed persistent-schema set. Its raw hash
remains the expected comparison hash; no normalized replacement baseline file is
created. Before/after fixture restoration uses the same comparison projection.
The target-column assertion remains independently enforced before fixture writes
and after rollback; it is not weakened by metadata normalization.

## Error and evidence flow

ON_ERROR_STOP remains on. Failure branches use a real PostgreSQL exception:
42501 for route/approval denial, P0001 for metadata mismatch. In psql -f mode this
terminates with nonzero status (normally 3 for script errors). Before the metadata
exception, output contains a metadata_check record with phase, expected/raw/
comparison MD5, temporary namespace inventory and full raw snapshot, followed by
a failure record identifying STAGE4_METADATA_MISMATCH. Target column diagnostics
are captured before their assertion as well.

The launcher keeps password entry directly attached to the operator's terminal;
it does not redirect or log stdin/passwords. Original PostgreSQL errors and
SQLSTATE are printed directly to stderr with VERBOSITY=verbose. On nonzero exit,
the parser reports the client exit and structured failure code FIRST, or directs
the operator to the original SQL error above if an unexpected failure emitted no
structured record. It never replaces that with Missing/ambiguous evidence.

Only after zero exit does it require exactly one correctly named success result,
the correct phase-specific matching metadata records and rollback acknowledgement.
Diagnostic records are not mistaken for duplicate success rows. Malformed JSON,
failure records with zero exit, duplicate success or missing acknowledgement fail.
No fixture/test/grant/policy change is inferred safe merely from a failed receipt.

## Historical evidence and pins

Original baseline, Stage3 evidence and Stage4 evidence/runtime.* are unchanged.
The failed receipt and empty output remain pinned for preservation. New future
attempts have separate evidence_r2/runtime.* and cleanup_check.* files, each
reserved once with CreateNew, and no automatic retry or deletion. This is a
reviewed harness revision, not permission to retry the failed operation now.

The shared target_guard.psql change affects consumers beyond Stage4. Historical
Stage3/bootstrap/no-DML manifests retain their original expected hash and were
NOT repinned or rerun. Old launchers that check that shared file will fail their
historical hash guard. This is intentional fail-closed behavior; any future reuse
of those launchers needs a separate review. Their historical PASS results remain
historical evidence, not approval to rerun them under changed dependencies.

Do not run build_stage4.py or the one-time review_harness_r2.py to bypass drift.
The pin updater refuses a second revision-2 refresh. Only explicitly allowlisted
files were changed; all other original script hashes were checked unchanged.

## Local validation results

- Stage4 pin/source/evidence/include checks PASS.
- Python AST and PowerShell parser checks PASS for revised launcher/helpers/tests.
- Offline normalization checks PASS: system temporary schemas ignored; arbitrary
  schema names and unverified temp-like names retained; persistent owner/ACL
  mutation, deletion/addition and unrelated grant/function drift remain failures.
- Nine synthetic result-parser cases PASS: native nonzero with empty output,
  metadata failure, failure record with zero exit, empty zero-exit result,
  success with diagnostic records, missing rollback acknowledgement, duplicate
  success, malformed JSON and wrong phase. No actual psql invocation in tests.
- Original baseline and failed receipt/output SHA-256 values match historical
  diagnostic manifest; baseline MD5 is unchanged.

These are static/offline tests, NOT PostgreSQL compilation, live metadata
comparison, interactive password behavior testing or Stage4 execution.

## Required next step: independent read-only TEST preflight

Open TEST SQL Editor, confirm URL project reference ikmzxirldivefebgxzaa, select
postgres, and only after read-only execution approval run the full contents of:

`C:\Users\APOORV\OneDrive\Desktop\MESH\meshcode\Mesh\supabase\testing\ikmzxirldivefebgxzaa\stage4\preflight_r2_read_only.sql`

This is one SELECT with CTEs, containing the same normalization predicate. It
does not invoke the launcher, set session options, create fixtures, execute DML
or change grants/RLS. It retains the independent raw diagnostic and adds:

- comparison_md5 must be `90a71db3b16ed177b3455f61a59343b2`;
- matches_expected, columns_match_expected, fixtures_absent and
  postgres_role_selected must all be true;
- ignored_temporary_namespaces must contain only the intended system namespaces.

Export full JSON for review. If any persistent metadata differs, investigate; do
not refresh the baseline or exclude more categories. SQL Editor output is not an
independent project-identity oracle, so Dashboard project confirmation is required.

Only after preflight review may a new explicit instruction authorize one corrected
Stage4 Runtime attempt and its separate read-only CleanupCheck. Existing limited
scope remains: ACL/helper/FK/control tests, no new API permissions, no Migration02,
no production and no claim of positive RLS filtering where SELECT is still denied.
