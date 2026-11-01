-- Zero-row statements exercise actual permission checks without reading rows or
-- inserting/updating/deleting data. Run before/after; compare with effective ACL.
DO $probes$
DECLARE r text; t text; op text; col text; expected boolean; actual boolean; stmt text;
BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated','authenticator','service_role','postgres'] LOOP
  FOREACH t IN ARRAY ARRAY['security_events','security_findings','security_incidents','incident_events','security_risk_scores'] LOOP
   col:=CASE WHEN t='incident_events' THEN 'event_id' ELSE 'id' END;
   FOREACH op IN ARRAY ARRAY['SELECT','INSERT','UPDATE','DELETE'] LOOP
    expected:=has_table_privilege(r,format('public.%I',t),op);
    stmt:=CASE op WHEN 'SELECT' THEN format('SELECT %I FROM public.%I WHERE false',col,t)
     WHEN 'INSERT' THEN format('INSERT INTO public.%I (%I) SELECT NULL::uuid WHERE false',t,col)
     WHEN 'UPDATE' THEN format('UPDATE public.%I SET %I=%I WHERE false',t,col,col)
     ELSE format('DELETE FROM public.%I WHERE false',t) END;
    actual:=true;
    BEGIN
     EXECUTE format('SET LOCAL ROLE %I',r);
     EXECUTE stmt;
     RESET ROLE;
    EXCEPTION WHEN insufficient_privilege THEN
     -- Subtransaction rollback restores the original role automatically.
     actual:=false;
    END;
    IF actual IS DISTINCT FROM expected THEN
     RAISE EXCEPTION 'DML probe mismatch: role %, table %, operation %, expected % actual %',r,t,op,expected,actual;
    END IF;
   END LOOP;
  END LOOP;
 END LOOP;
END $probes$;
