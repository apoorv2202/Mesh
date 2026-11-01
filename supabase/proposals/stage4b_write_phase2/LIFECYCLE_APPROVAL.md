# Lifecycle approval / execution gate still closed — 2026-10-31

The human user explicitly approved the Stage 4B-write lifecycle contracts in this
chat's local authorization-gate preparation request: status transitions, assignment
and offboarding behavior, and documented audit-retention exceptions. This record
does not approve database execution, deployment or any production action.

The approved document is the existing, unchanged CONTRACTS.md with SHA-256:

`cab704d5511a210dcd39fe3b8ac18d52980f6f49a7600a79b9940c02d166d9cb`

Earlier text describing lifecycle approval as pending is superseded by this
record, not by edits to the approved contracts. PostgreSQL compilation, ownership,
catalog assumptions, runtime concurrency and authentication remain unverified.
The last independent review recommended requesting authorization for the limited
rollback tier; that recommendation is not authorization to perform it.

## Gate state and next prerequisites

execution_readiness.json records lifecycle approval separately from the gate:
authorizable=false and database_execution_authorized=false. The preparation
manifest also retains execution_authorized=false. Lifecycle approval is not read
by the launcher as permission to run. The existing Runtime guard rejects execution
before invoking psql. No launcher branch or authorization protection was changed.

A future attempt still requires explicit TEST-only runtime authorization, a
separately approved local gate change, regenerated/reviewed pins and their new
manifest hash, the reviewed Windows psql/CA configuration, and interactive TEST
authentication. Fresh read-only cleanup remains separately scoped. Neither Runtime
nor CleanupCheck was invoked by this task. No retry or connection was attempted.

## Exact local change inventory

Modified:

1. supabase/testing/ikmzxirldivefebgxzaa/stage4b_write_phase2/execution_readiness.json:
   record lifecycle approval and approved-document hash; retain false execution
   flags; replace the resolved lifecycle-review prerequisite with explicit future
   execution authorization/gate/pin prerequisites.
2. Same directory README.md: add the current approval/gate status without erasing
   earlier preparation/review history.
3. Same directory update_preparation_pins.py: preparation revision label v4 only.
4. Same directory pins.json: regenerate hashes using the existing local tool.
5. supabase/proposals/stage4b_write_phase2/changed_preparation_files.json:
   regenerate the tool's cumulative preparation change inventory.

Added:

6. This LIFECYCLE_APPROVAL.md approval record.
7. review_archive/pins.before_lifecycle_approval.json: exact copy of the preceding
   116-entry manifest, SHA-256
   `30262be58d3c80ed82a483a3efe8eb920d0de00195b11c46e1fe28ce3faaeb7d`.

No SQL candidate, generator of database SQL, generated SQL/object/ACL contract,
launcher, test case, historical evidence, R2/read pins, Phase 1 hash or trusted
baseline was modified. Original CONTRACTS.md bytes remain unchanged.

Offline checks cover all preparation and historical pins, explicit function
ownership against both manifests, model/negative/parser regression tests and
PowerShell syntax. They do not compile or execute PostgreSQL SQL. The gate must
remain false throughout preparation and validation.
