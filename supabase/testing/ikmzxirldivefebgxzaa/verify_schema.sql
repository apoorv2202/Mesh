-- Read-only metadata; expected public application totals: 18/165/85/46/18.
\set ON_ERROR_STOP on
\ir target_guard.psql
BEGIN READ ONLY;
-- One JSON result, preserving the existing 12-section inventory format.
-- Routine bodies remain withheld in this verification export by default.
\ir ../../inspection/master_inspection.sql
COMMIT;
