SAVEPOINT documented_gaps;
UPDATE public.security_risk_scores SET subject_id='44444444-4444-4444-8444-000000000015' WHERE id='44444444-4444-4444-8444-000000000020';
UPDATE public.security_events SET actor_user_id=:'user_b'::uuid WHERE id='44444444-4444-4444-8444-000000000012';
UPDATE public.security_incidents SET assigned_to=:'user_b'::uuid WHERE id='44444444-4444-4444-8444-000000000016';
-- These succeed as owner: known missing constraints, NOT a tenant-security PASS.
ROLLBACK TO SAVEPOINT documented_gaps;
