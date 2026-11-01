-- OPTIONAL TEST DATA ONLY. Not included/executed by the bootstrap or launcher.
-- Review/approve separately after schema verification. No Auth users or passwords.
\set ON_ERROR_STOP on
\ir target_guard.psql
\if :{?vader_seed_approved}
\else
\echo Synthetic seed not approved.
\quit 3
\endif
SELECT :'vader_seed_approved'='ikmzxirldivefebgxzaa' AS seed_ok \gset
\if :seed_ok
\else
\quit 3
\endif
BEGIN;
INSERT INTO public.organizations(id,name,status) VALUES
 ('11111111-1111-4111-8111-111111111111','VADER disposable A','active'),
 ('22222222-2222-4222-8222-222222222222','VADER disposable B','active');
COMMIT;
