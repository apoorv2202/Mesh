\ir guard.sql
BEGIN;
SET LOCAL statement_timeout='60s';
\ir dml_probes.sql
SELECT jsonb_build_object('test','dml','passed',true,'probes',100) AS result;
ROLLBACK;
