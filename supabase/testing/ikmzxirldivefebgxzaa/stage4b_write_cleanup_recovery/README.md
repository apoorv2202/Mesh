# Read-only cleanup recovery — LOCAL PREPARATION ONLY

TEST: ikmzxirldivefebgxzaa. Production is prohibited. No recovery authorization or
database execution is granted by preparation, pins or offline test results.

## Entry point and preserved evidence

`Invoke-CleanupRecovery.ps1` supports ONLY cleanup. It has no Runtime/SQL-file/
host/user override. New outputs will be under `evidence/attempt_01/`: receipt.json,
result.txt, native_stdout.txt and stderr.txt. That directory is NOT created during
preparation. An existing directory or reservation stops execution without retry.
CreateNew receipt reservation prevents a concurrent invocation from taking the
same attempt. Output files are reserved before process start. The receipt is
written through the original exclusive reservation handle, not by overwriting an
existing receipt. No original evidence is renamed, copied as a success, or opened
for writing.

All six original Runtime/CleanupCheck files stay in stage4b_write_phase2/evidence.
Their exact SHA-256 values are frozen in prepare_manifest.py and change_inventory.json
and pinned as immutable recovery inputs. Original failed receipt statuses remain
false. A future recovery PASS means current restoration verified, not that either
previous attempt passed.

The original Runtime receipt/log still supplies the pre-attempt ACL fingerprint
e4e671b562707df52adc76c3c26e14af, bound to original manifest SHA
9ce235e2887aea69bc0772c09ff8e646412cb845ce97cfd8df96e6d52976df68.
The new recovery manifest has its own distinct hash. These identities are not
interchangeable. The original reviewed manifest and all 123 source pins remain
unchanged; existing historical read/Phase 1 pins are also verified.

## Authorization, SQL and target guards

Future execution requires BOTH `-ApproveCleanupRecovery` and the exact newly
reviewed recovery manifest SHA. These are per-invocation requirements following
explicit human authorization, not an authorization supplied by this document.
Persistent execution_authorized and database_execution_authorized stay false.
Inputs are hash checked before helper code is loaded. Wrong project, source drift,
missing approval, stale hash, unavailable console or existing evidence fail closed.

The entry invokes unchanged ../stage4b_write_phase2/cleanup_check.sql, with all ten
reviewed read-only SQL dependencies and exact metadata/ACL/collision assertions.
Connection default_transaction_read_only=on and BEGIN READ ONLY both remain.
Expected metadata MD5 is 90a71db3b16ed177b3455f61a59343b2. No migration, Runtime,
grant, fixture or helper-EXECUTE correction is included. Native role/permission,
object and fixture absence must match the original baseline. SQL dependencies
are pinned; there is no arbitrary script argument.

The fixed session-pooler host is aws-0-eu-west-1.pooler.supabase.com, port 5432,
database postgres, user postgres.ikmzxirldivefebgxzaa. TLS sslmode=verify-full and
the original CA SHA-256 are enforced. Windows psql product version 18.6 is required.
Certificate CA flag, dates and no private key are checked before reserving an
attempt. No --linked Supabase CLI commands are used.

## Password and native-process handling

Use a real interactive ConsoleHost in the user's own Windows terminal. Native
CONIN$/CONOUT$ handles and unredirected parent input/output are required before an
attempt is reserved. `-W` invokes psql's supported no-echo password prompt. Enter
the TEST password ONLY at that prompt; never send it through chat or shell arguments.

ProcessStartInfo leaves child stdin unredirected and keeps the console attached.
No password is collected by PowerShell, logged, passed as an argument or placed
in environment variables. PG* overrides are removed from the CHILD environment,
and fixed safe settings are supplied; the parent environment is unchanged. OSTYPE
is removed to avoid the known MSYS fallback path. PGPASSFILE is pointed beneath
the reserved regular result.txt file, an unusable path, solely to disable libpq's
default persistent password-file fallback. No password file is created or read
by this workflow. That variable contains a path, never a credential.

Both native stdout/stderr are drained concurrently using Process APIs. Stderr is
captured as data, avoiding PowerShell NativeCommandError aborting before exit-code
recording. Nonzero exit always fails BEFORE parsing success-shaped JSON. Ordinary
missing-password, authentication and SQL errors therefore retain their exit status
and stderr. Process-start/I/O failures may still yield null exit status; they are
recorded as failures, never interpreted as success. Cancellation or a host crash
can leave an incomplete reservation: preserve it and investigate, never reuse it.

## Offline validation

`prepare_manifest.py --prepare-local-manifest` prepares only local metadata after
verifying all original source/evidence hashes. `validate_offline.py` reads pins,
original evidence and the SQL include closure without invoking recovery or psql.
`Test-RecoveryOffline.ps1` exercises helper and actual entry approval guards,
wrong projects, evidence collision/CreateNew reservation, synthetic credential/
authentication/SQL failures, nonzero native exit/stderr and result parsing.
Native dummy commands contain only fixed synthetic strings, not SQL/credentials.
A dummy-only stdin transport check is separate from the real console check.

The local tool environment may be headless. In that case the console test MUST
reject it before attempt reservation. Dummy stdin success is not proof that the
user's psql no-echo prompt works. A positive end-to-end interactive-console test
remains a limitation unless separately observed. Offline tests never call this
recovery entry point, psql or either database.

## Proposed later command — NOT authorized now

After independent local review and separate authorization of one recovery attempt:

```powershell
& .\supabase\testing\ikmzxirldivefebgxzaa\stage4b_write_cleanup_recovery\Invoke-CleanupRecovery.ps1 -ApproveCleanupRecovery -ReviewedManifestSha256 '<new-independently-reviewed-recovery-manifest-sha256>'
```

If a prompt is missing, empty or fails, stop. No automatic retry, evidence cleanup,
manual SQL/grants or altered TLS settings are permitted. Inspect receipt, exit
status and hashes, and compare the exact baseline result before claiming restored.
The previous authorization was consumed; this preparation is not permission to run.

## Inventory and remaining risks

All new files are confined to this recovery directory; change_inventory.json lists
them. No original file is modified. No real attempt directory is created. Actual
authentication and PostgreSQL restoration remain UNVERIFIED until a separately
authorized recovery succeeds. Native console availability in the user's actual
terminal, process cancellation/host-crash evidence completeness and PostgreSQL
metadata/deparser assumptions remain runtime risks. Hashes are local integrity
checks, not tamper-proof signatures against an administrator.
