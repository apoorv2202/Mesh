# Independent Stage4 metadata drift diagnosis

Status: PREPARED ONLY. Stage4 remains NO-GO. No PostgreSQL query, runtime test,
fixture creation or correction has been executed by this package.

TEST ONLY: `ikmzxirldivefebgxzaa`. Production `khweikfvsnervfuswhon` is prohibited.
No credentials are needed to prepare/compare files; never send passwords, API keys
or JWTs to the agent or place them in these artifacts.

## Exact reproduction and evidence preservation

`capture_metadata_read_only.sql` is one SELECT with CTEs. Its materialized
snapshot_capture contains the original stage3/snapshot.sql SELECT verbatim,
including original ordering, qualification, null handling and catalog scope.
Only the psql-only `\gset` suffix is omitted; its captured value is instead
returned as `snapshot_text`. Server `md5(snapshot::text)` is the same expression
represented by runtime's `md5(:'snapshot')` after psql variable substitution.
No JSON normalization, key reordering, session SET or baseline replacement is done.

Expected baseline MD5: `90a71db3b16ed177b3455f61a59343b2`.
Offline Python and the existing PowerShell UTF8/Trim calculation agree.
The pinned baseline is ASCII without a UTF8 BOM, so those encoding differences
do not explain the previously observed failure.

All original Stage4 scripts, pins, trusted baseline and failed-run receipt/output
are unchanged. `diagnostic_manifest.json` records source/baseline/failed-evidence
hashes and the new diagnostic SQL hash; it is NOT a replacement runtime manifest.
The offline preparation script writes only this independent diagnostic package.

## Execution in Supabase SQL Editor

1. Open the TEST Dashboard and visibly confirm the URL/project ref is
   `ikmzxirldivefebgxzaa`. Do not open or run anything in production.
2. Select SQL Editor role **postgres**. No database password need be shared.
3. Open this file locally, copy its complete contents into a new TEST SQL Editor
   query, and execute it once:

   `C:\Users\APOORV\OneDrive\Desktop\MESH\meshcode\Mesh\supabase\testing\ikmzxirldivefebgxzaa\stage4_diagnostics\capture_metadata_read_only.sql`

4. Export the complete one-row result as JSON, preferably to
   `stage4_diagnostics/metadata_diagnostic_result.json`. The grid may visually
   abbreviate this large snapshot; do not copy a truncated cell or screenshot.
5. Return the export for analysis. It includes snapshot metadata and targeted
   counts only, no credential values, application rows or raw helper definitions.
   Routine bodies/settings are hashed exactly as the original snapshot did.

The project ref in the result is a client assertion, not an independent database
identity proof. SQL Editor project selection is mandatory. If postgres/catalog
permissions are unavailable, stop; do not grant access or change the query to
hide inaccessible objects. Do not run runtime.sql, CleanupCheck or any launcher.

This SELECT does not SET transaction_read_only or any other session setting,
because it must observe the current session without normalizing it. Its query
and nested CTEs use SELECT only: no DDL/DML, BEGIN/COMMIT, fixture operations,
set_config, sequences mutation or runtime/control probes.

## Captured fields

- Actual complete original snapshot text, server MD5, expected MD5 and hash equality.
- current_user, session_user, database, postgres-role selection and BYPASSRLS flag.
- Whitelisted serialization/deparser/session settings: server/client encoding,
  server version, search_path/current_schemas, quote_all_identifiers, DateStyle,
  IntervalStyle, TimeZone, extra_float_digits, bytea_output, standard-conforming
  strings, role, row_security, replication role and transaction modes/locale.
  No unrestricted GUC dump, connection parameters or secrets.
- Supplemental exact definitions for the five tables' columns, since the original
  M01 snapshot did not include columns. These do not alter the hashed snapshot.
- Supplemental relation/routine OID-to-name labels for interpreting differences.
- Fixture collision/absence counts across all organizations: supplied profiles/
  memberships, reserved organizations, asset/event/finding/incident/risk UUIDs,
  FK-negative UUIDs 80/81/82, incident-link references, and incident numbers
  -44001/-44002/-44999. No Auth tables are queried for this cleanup diagnosis.

`fixture_status.fixtures_absent` must be true with all counts zero. It is a
conservative namespace-clean result: an existing profile/membership for one of
the supplied identities also makes it false, even if unrelated to this test.
This SELECT neither cleans up nor deletes anything.

## Local comparison after export

The comparison script accepts the raw JSON value or Supabase's one-row JSON export
wrapper. It validates baseline integrity and actual snapshot text/hash agreement,
compares parsed JSON without replacing the original MD5 comparison, and reports
added/removed/changed records and field values for each captured category.

```powershell
python "C:\Users\APOORV\OneDrive\Desktop\MESH\meshcode\Mesh\supabase\testing\ikmzxirldivefebgxzaa\stage4_diagnostics\compare_metadata.py" `
  "C:\Users\APOORV\OneDrive\Desktop\MESH\meshcode\Mesh\supabase\testing\ikmzxirldivefebgxzaa\stage4_diagnostics\metadata_diagnostic_result.json" `
  --output "C:\Users\APOORV\OneDrive\Desktop\MESH\meshcode\Mesh\supabase\testing\ikmzxirldivefebgxzaa\stage4_diagnostics\metadata_comparison.json"
```

Output uses exclusive file creation, not overwrite. This command is entirely local
and cannot connect to PostgreSQL or change records. It reports relations/tables,
columns, constraints, indexes, policies, effective/table/column grants, functions,
role attributes/memberships, schemas/default ACLs, event triggers, ordinary triggers,
sequences and target RLS. Arrays are additionally compared by original catalog
identity to distinguish ordering-only changes; original hash/equality still stand.

Full exact field differences are retained in the local comparison JSON. Function
changes initially identify owner/ACL/settings-hash/definition-hash differences;
raw bodies cannot be reconstructed from hashes. The tables comparison covers
captured pg_class ownership/ACL/RLS fields, not uncaptured storage/row statistics.
Column comparison is limited to five target tables using the earlier full export.

## Interpretation and next action

- Same hash and snapshot now: current state matches, but the earlier mismatch's
  cause is NOT proven because that failed-run snapshot/session was never saved.
- Different hash with identical parsed JSON: textual representation difference;
  inspect captured session/encoding settings without weakening assertions.
- Different captured values: inspect exact category changes. Function definition
  hashes may depend on deparser/search_path context. Real catalog changes and
  session effects cannot always be distinguished from a single SQL Editor capture.
- SQL Editor may use a different session_user/search_path than the original pooler
  psql connection. No original session-settings baseline exists. A subsequent
  same-route read-only capture might be needed; this package does not authorize
  changing settings, accepting drift, regenerating pins or rerunning Stage4.

After actual differences are reviewed, propose the smallest correction separately.
The invalid `\quit 3` and missing diagnostic-output issues remain unchanged and
need a later review. Preserve failed evidence; no correction is implemented here.

Current deliverable: expected hash known; actual hash UNAVAILABLE, exact live
differences UNAVAILABLE, fixture absence UNVERIFIED. No usable authenticated
read-only connection is available to the agent without interactive access; this
SQL Editor handoff avoids requesting or handling credentials. Keep Stage4 NO-GO.
