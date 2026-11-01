-- SELECT only, no data mutations. BYPASSRLS does not supply absent table ACLs.
DO $denied$
DECLARE r text; t text; blocked boolean; n bigint; probes int:=0;
BEGIN
 FOREACH r IN ARRAY ARRAY['anon','service_role','authenticator'] LOOP
  FOREACH t IN ARRAY ARRAY['security_events','security_findings','security_incidents','incident_events','security_risk_scores'] LOOP
   blocked:=false;
   BEGIN
    EXECUTE format('SET LOCAL ROLE %I',r);
    EXECUTE format('SELECT count(*) FROM public.%I',t) INTO n;
    RESET ROLE;
   EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
   END;
   IF NOT blocked THEN RAISE EXCEPTION 'Unexpected SELECT for %, %',r,t; END IF;
   probes:=probes+1;
  END LOOP;
 END LOOP;
 IF probes<>15 THEN RAISE EXCEPTION 'Incomplete restricted-role SELECT probes'; END IF;
END $denied$;
SELECT jsonb_build_object('record_type','restricted_role_reads','passed',true,'assertions',15) AS result;
