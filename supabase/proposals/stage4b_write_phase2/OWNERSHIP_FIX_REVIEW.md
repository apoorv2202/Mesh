# Ownership contract generator correction — 2026-10-31

**GO for another independent local review. NO-GO for database execution.**
The runtime readiness gate remains false. No database connection, SQL execution,
migration, grants, fixtures or runtime harness execution occurred.

## Root cause and narrowly scoped correction

The previous owner regex required at least one character between parentheses,
so tenant_v1() was missed and silently assigned postgres. It also matched only
by function name, which was unsafe for overloaded signatures.

ownership_parser.py now scans top-level SQL statements while respecting comments,
quoted strings and dollar bodies. Ownership keys are (schema, name, ordered IN
argument types), including empty argument lists. Recognized type aliases are
canonicalized for identity matching. Statements must refer to an earlier matching
CREATE FUNCTION signature and an approved owner. Unrecognized ALTER FUNCTION,
ALTER ROUTINE/PROCEDURE, malformed syntax, unknown overloads, duplicate creates,
unsupported identifier/mode/default syntax or missing transfer fail closed.

No missing-transfer fallback is permitted except three explicitly enumerated
postgres-owned helper signatures: machine_scope_v1(), human_guard_v1(uuid,uuid),
triage_token_v1(text,jsonb). A protected helper cannot be transferred to another
owner. Repeated transfers retain their full chronological history; the final
transfer determines the final object/ACL owner. The generator does not execute SQL.

tenant_v1() now has vader_writer_owner in both object_contract.json and its ACL
owner/grantor tuple. Exact ownership/ACL assertions are preserved, not weakened.
The generated assertion files embed the corrected manifests. Proposal SQL, role
provisioning, actual grants, business contracts and runtime transaction logic are
unchanged in this correction.

## Independent agreement and regression validation

verify_ownership_contracts.py uses a separate, constrained extractor for the actual
reviewed ownership statements. It compares all 13 explicit transfers with the
object manifest, their final ACL owner/grantor tuples and the embedded assertion
manifests. It also verifies all 16 function ACL signatures and the three explicit
creator-owned helpers. This check is part of normal offline/static validation.

17 new regression tests pass: empty arguments, arguments, signature-specific
overloads, multiple transfers/history, same names in different schemas, aliases,
named IN arguments/default NULL, explicit creator defaults, unknown/default owners,
unknown targets, missing/malformed/unrecognized transfers, ignored comment/body
text, duplicate creates and actual SQL-to-object-to-ACL agreement.

All 35 pre-existing offline/model tests also pass: 12 original, 9 Phase 2, 14 ACL
negative tests. Total: 52 tests. Static include/transaction/body-equivalence checks
and PowerShell AST parsing pass. Neither the launcher nor a PostgreSQL parser was
executed. Historical Phase 1 hashes and Stage 4B-read pins/receipt hashes match.

## Changed files and preparation artifacts

Modified:

* build_object_contract.py — signature-aware parser and complete transfer history.
* object_contract.json and acl_contract.json — corrected tenant owner/ACL.
* generated assert_object_contract.sql and assert_acl_exact.sql.
* validate_offline.py — independent ownership audit is mandatory.
* update_preparation_pins.py — preparation revision label v3.
* changed_preparation_files.json and pins.json — regenerated local preparation data.

Added:

* ownership_parser.py — import-safe constrained SQL parser.
* ownership_regression_tests.py — memory/text-only regression suite.
* verify_ownership_contracts.py — independent read-only manifest audit.
* this review and review_archive/pins.before_ownership_parser_fix.json.

The preceding 111-entry preparation manifest is preserved in that archive. The
older archive, all historical R2/read evidence, Phase 1 files and trusted baseline
remain unchanged. Preparation repinning rejects historical-file changes. Pins
authenticate file content, not database correctness or execution authorization.

## Remaining risks

This is a deliberately constrained parser for the reviewed SQL subset, not a
general PostgreSQL compiler. Quoted identifiers, OUT/INOUT/VARIADIC modes, arbitrary
default expressions and type modifiers require explicit parser extension/review;
they are rejected rather than guessed. Supported overloads use explicit ordered
IN argument types. The independent audit is likewise constrained to current
reviewed ownership statement syntax, separate from the generator implementation.

Actual PG17 compilation, Supabase ownership/creator behavior, ACL grantor choice,
TOAST/deparser assumptions, real LOGIN/JWT and database concurrency remain
unverified. Status/assignment/audit-retention contracts still require review.
No runtime-gate change or execution authorization is part of this correction.
