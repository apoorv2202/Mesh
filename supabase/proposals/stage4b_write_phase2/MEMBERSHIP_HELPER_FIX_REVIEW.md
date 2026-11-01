# Membership helper permission correction â€” local preparation only

GO for independent local review; no database execution authorization.

## Root cause

The failed Runtime receipt identifies 04_human_triage.body.psql:36, P0001,
Existing membership helper EXECUTE prerequisite absent. build_candidates.py had
replaced the Phase 1 grant with a prerequisite assertion. The captured helper ACL
grants postgres/authenticated execution, not the newly created triage owner.
The public schema USAGE check passed first. This was not a signature mismatch.

## Exact correction

Restore GRANT EXECUTE ON FUNCTION public.is_mesh_member(uuid,public.mesh_role[])
TO vader_triage_owner, after role creation and before the existing privilege
assertion. No PUBLIC grant, grant option, managed membership, function definition,
owner, signature, schema, SECURITY DEFINER setting or search path change.

The independent ACL oracle increases from 145 to 146 additions, with exactly one
new tuple: function / public.is_mesh_member(uuid, public.mesh_role[]) / empty
column / postgres grantor / vader_triage_owner / EXECUTE / grantable=false.
The existing global metadata guard allows only this OID's ACL to differ; every
other captured helper field must match, and all other function rows remain exact.
The exact ACL assertion compares all before/after helper tuples, preserving
existing grantees and rejecting any additional change. It takes baseline helper
ACLs from the original metadata snapshot, not from the post-grant catalog.

capture_acl.sql and the original e4e671b562707df52adc76c3c26e14af fingerprint scope
remain unchanged. The helper is included separately in the installed-state oracle.
Rollback metadata equality already includes all pg_proc ACLs, so restoration of
the original helper ACL is required. Fresh cleanup retains the same baseline.

## Validation and preservation

62 offline tests passed: 9 helper, 9 lifecycle/failure model, 14 ACL-negative,
17 ownership parser, 13 authorization gate tests. Ownership audit: 13 transfers,
16 created function signatures, 3 explicit creator-owned helpers. The existing
helper is not a newly created seventeenth function. PowerShell syntax parsing
passed for both existing PS1 files; launcher code is unchanged.

membership_fix_inventory.json records per-task changes, unlike the cumulative
changed_preparation_files.json. review_archive/pins.before_membership_helper_fix.json
preserves the original 9ce235... reviewed manifest byte-for-byte. All original
Runtime/CleanupCheck and recovery evidence bytes, recovery source files and
recovery manifest are unchanged. Historical 53 read and 11 Phase 1 hashes match.

The completed recovery manifest pins the previous mutable Phase 2 source revision;
it is historical evidence and must not be regenerated or reused after this source
correction. Its recorded recovery success remains valid. No claim is made that
its old source pins match the corrected candidate. The new candidate has new pins.

## Remaining risks / NO-GO for execution

No PostgreSQL compilation, grantor behavior, effective permission or Supabase
event-trigger behavior has been tested for this revision. Both persistent
execution authorization flags remain false; prior authorization is consumed.
The original launcher still has occupied evidence slots and its previously
diagnosed native stderr handling limitation. This task does not fix the launcher,
prepare new execution slots, or authorize a retry. A separately reviewed future
execution/evidence procedure is required before any new TEST attempt.
Production remains excluded. No database connection or SQL execution occurred.
