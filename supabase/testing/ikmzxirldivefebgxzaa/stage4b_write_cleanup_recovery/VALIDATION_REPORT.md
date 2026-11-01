# Cleanup recovery preparation — 2026-10-31

**GO for independent LOCAL review only. NO-GO for database execution now.**
No psql, Runtime, CleanupCheck or recovery entry point was executed. No connection,
SQL, password, attempt directory or fixture was created. All new artifacts are
confined to this recovery directory and change_inventory.json lists them.

## Preserved originals

All six original Runtime/CleanupCheck files match the exact previously recorded
hashes. Original failed receipts remain passed=false with their original null
exit codes. The original manifest SHA is unchanged:
9ce235e2887aea69bc0772c09ff8e646412cb845ce97cfd8df96e6d52976df68.
All 123 original source pins, 53 historical read pins and 11 Phase 1 hashes remain
unchanged. No original launcher, SQL proposal, authorization flag or baseline was
modified. Those historical failures are neither relabeled nor copied into a new
attempt. Recovery pins reference the original paths and exact bytes.

## Tests actually performed

* Read-only static checks: ten unchanged cleanup SQL dependencies, BEGIN READ ONLY,
  default_transaction_read_only=on, fixed TEST/TLS/CA/client, no Runtime/SQL override,
  explicit approval/new SHA, pre-import helper pinning, unredirected child stdin,
  child-only sanitized environment and one native invocation without retry.
* PowerShell helper and actual entry approval checks reject missing approval and
  stale hash. Wrong projects and unexpected authorization are rejected. Existing
  evidence directories and duplicate CreateNew reservation are rejected.
* Synthetic native commands (Windows cmd.exe, no database client) emit missing-
  credential, authentication-failure and SQL-failure diagnostic text with exit 2.
  All exit codes and stderr are retained under ErrorActionPreference=Stop. Nonzero
  exit rejects even success-shaped JSON. Empty/duplicate result records reject.
* A child dummy-stdin test receives only DUMMY_ONLY_123 and returns a fixed success
  marker. The value is synthetic, not a password and not a connection parameter.
* ConsoleProbe compiled locally. The tool environment reports real-console access
  false; the live-console precondition correctly rejects this environment before
  any attempt reservation. Total observed offline assertions: 26.
* PowerShell AST syntax and preparation manifest/evidence hashes are validated
  without invoking recovery. No execution-policy setting is changed.

## Limits before execution

The dummy stdin test does not establish psql's CONIN$ prompt in a human terminal.
Positive, non-echoing native interactive-console behavior in the user's actual
terminal is not verified here. This limitation is explicit; no secret was requested.
The recovery launcher must refuse headless/piped use. A real console and interactive
TEST password are prerequisites for a later separately authorized recovery.

This proposal uses Process APIs to fix ordinary native-error capture; it cannot
guarantee a final receipt after a host crash, forced termination or process I/O
failure. An incomplete reservation must remain evidence and must never be reused.
The helper's actual-process path has only been tested with synthetic native
programs. Authentication/restoration remain UNVERIFIED until an authorized test.

The new entry point, transport, evidence location and manifest require independent
review and fresh explicit execution authorization. No earlier authorization is
reused. No approved helper EXECUTE grant or other Runtime correction is applied.
