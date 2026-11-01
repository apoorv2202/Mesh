# Eligibility tooling correction — 2026-10-31

**Local eligibility prepared. Database execution remains unauthorized.**
No SQL, connection, runtime/cleanup harness invocation, migration, fixture or
historical evidence change is part of this task.

## State machine and unchanged launcher boundary

Two preparation states are supported: sealed_not_authorized (authorizable=false)
and eligible_not_authorized (authorizable=true). BOTH require literal false
database_execution_authorized and manifest execution_authorized. Lifecycle approval
and its exact contract SHA are required; unknown/missing readiness fields, wrong
types, unknown manifest structure/scope, missing approval or stale contract binding
are rejected. There is no persistent authorized-execution state in this tooling.

The actual launcher requires -ApproveTestRollback AND an exact reviewed manifest
SHA before reading readiness or entering either Runtime/CleanupCheck branch.
Eligibility alone cannot satisfy this common guard. No launcher or SQL modification
was needed or made. These metadata flags do not supply per-invocation approval.
Unexpected readiness fields fail closed in preparation; post-pinning file changes
also invalidate the launcher's file hashes. This is not a new runtime JSON-schema
check; the unchanged launcher still uses its existing pinned-file trust boundary.

The current authorizable=true records the user's approved eligibility transition.
database_execution_authorized=false and execution_authorized=false remain intact.
PostgreSQL compatibility questions remain future runtime checks, not claims of
successful database testing. No runtime/cleanup approval has been received.

## Files changed

Modified:

* execution_readiness.json — eligibility true; explicit per-invocation prerequisite;
  both execution-authorization flags remain false in their respective files.
* update_preparation_pins.py — shared strict state validation instead of requiring
  eligibility false; new local preparation revision label, no execution support.
* validate_offline.py — same state validation. A narrowly scoped explicit
  --preparing-eligibility-repin mode permits only the five reviewed preparation
  file changes while retaining all historical/SQL/launcher hash checks. Normal
  validation accepts no hash mismatches. This mode never launches anything.
* README.md — distinguish current eligibility from execution authorization.
* changed_preparation_files.json and pins.json — regenerated AFTER corrected
  pre-repin validation succeeds, using the existing explicit preparation tool.

Added:

* gate_state.py — import-safe strict preparation-state validator.
* gate_regression_tests.py — 13 in-memory state/schema regression tests.
* Test-ApprovalGuardOffline.ps1 — extracts and tests ONLY the actual approval IF
  statement, never the launcher or any connection/execution branch.
* This review and review_archive/pins.before_gate_eligibility_tooling.json — the
  preceding unchanged 118-entry preparation manifest is preserved.

All SQL, generators of SQL, object/ACL contracts, runtime/cleanup scripts, launcher,
previous archives, lifecycle contract/approval record and historical artifacts are
unchanged. The previous LIFECYCLE_APPROVAL record describes an earlier closed state;
this later approved eligibility transition supersedes that status only.

## Offline validation and negative cases

65 Python tests: 52 existing offline/model/parser cases plus 13 new preparation
state tests. These reject true execution flags, missing lifecycle approval, stale
contract binding, wrong projects/scope, unknown/missing fields, invalid booleans
and malformed preparation state. Both sealed and eligible states are accepted
only without execution authorization.

20 PowerShell cases exercise the unchanged common approval guard in isolation,
using local file hashing only: both action labels, both eligibility values and
five explicit-approval/hash combinations. Missing approval and missing/stale hash
are rejected, including when eligibility is true. Matching approval/hash only
passes the isolated IF statement; NO later launcher statement runs. AST text must
match the reviewed guard exactly or the offline test stops.

Windows blocked direct .ps1 invocation with an AuthorizationManager error. The
isolated offline test body was then evaluated from its parsed AST with an explicit
local source path, without changing execution policy. All 20 cases passed. The
launcher and its Runtime/CleanupCheck branches were never invoked.

Ownership checks still cover 13 explicit transfers and 16 function ACL signatures.
Historical pin/receipt checks, include/transaction/body assertions, PowerShell
syntax and preparation pins are revalidated. No guard tests are evidence of a
database connection, PostgreSQL compilation, authentication or runtime PASS.

## Remaining prerequisites

Separate human authorization remains required for any TEST Runtime or CleanupCheck
invocation, naming scope and exact newly reviewed manifest hash. Reviewed client/CA
and interactive authentication are still required. Stop on any error with no retry.
Real LOGIN, JWT, PostgreSQL ownership/catalog behavior and concurrency remain
unverified; managed roles, production and permanent migrations are untouched.
