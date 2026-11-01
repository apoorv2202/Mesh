# Local preparation result — 2026-10-30

**NO-GO for database execution. Local preparation and offline checks completed.**

Interrupted session saved five files: `01_audit_permissions.sql`,
`02_reference_integrity.sql`, `04_human_triage.sql`,
`machine_support.sql.in`, `build_machine_candidate.py`. Git tracks the entire
proposals directory as untracked, so attribution is based on recovered files and
prior session context, not a historical Git diff. Unrelated work was untouched.

Resumed work generated `03_machine_writer_r2.sql` and
`machine_revision_source.json`, added README, offline contract tests, static
validator, this report and new local preparation pins. Minor recovered-file
corrections: explicit JSON key alias in triage; fail closed on NULL machine audit
action/type; strengthen FK prerequisite checks to include source/target tables.
Original Migration 02 was not modified.

## Offline results

* 12 memory-only unit tests passed, including thread contention, stale state,
  offboarded replay, tenant/reference denial, restricted fields, immutable risk
  identity, replay conflict and machine/human audit failure rollback.
* Static validator passed four SQL proposal lexical/closed-gate checks and
  public INSERT column checks against captured catalogs. It is not a SQL parser.
* All 53 historical Stage 4B-read pins match; these cover trusted baseline and
  historical Stage 4 dependencies. No repinning of historical files occurred.
* Original Migration 02 SHA-256 matches the source manifest.
* No database client, network connection, SQL, fixture or runtime harness ran.
* Local Python emitted a location warning but executed all scripts successfully.

## Limitations and next authorization

The memory model does not execute these SQL functions; its global lock cannot
prove PostgreSQL lock ordering, offboarding races, deadlock behavior or isolation
levels. Tests do not establish actual status-transition implementation correctness,
real authentication or API exposure safety. There is no executable network runner.

Before TEST execution: approve transition/assignment/audit lifecycle decisions;
review full FK definitions and all column/effective ACLs; verify role creation and
ownership capability; add independent pre-COMMIT assertions for API helper EXECUTE,
owners, membership and exact permission deltas. Prepare a separately reviewed
TEST-only TLS-verified, hash-pinned rollback runner. Review intentional native-schema
ACL deltas inherited from original 02. Do not treat the test_ref GUC as proof of
project identity. No original completed write-design report was present under the
searched design/closure filenames; approved user direction and preserved original
proposal supplied the available architecture, with choices recorded in README.

Rollback strategy and per-operation authorization/field matrix are in README.
No reverse SQL is claimed safe for committed historical data without a new review.
