SELECT md5(:'comparison_snapshot')=:'expected_post_md5' AS post_matches \gset
\if :post_matches
\else
SELECT jsonb_build_object('record_type','failure','code','STAGE4_METADATA_MISMATCH',
 'phase',:'metadata_phase','expected_md5',:'expected_post_md5',
 'raw_md5',md5(:'raw_snapshot'),'comparison_md5',md5(:'comparison_snapshot')) AS diagnostic;
DO $fail$ BEGIN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='STAGE4_METADATA_MISMATCH: captured diagnostic precedes this error'; END $fail$;
\endif
