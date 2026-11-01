"""Prepare independent SELECT-only validation of the correction; never runs SQL."""
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parent
diagnostic=(ROOT.parent/'stage4_diagnostics/capture_metadata_read_only.sql').read_text().rstrip().removesuffix(';')
helper=(ROOT/'capture_comparison.sql').read_text()
start=helper.index('WITH recognized_temporary AS (')
end=helper.index('SELECT jsonb_set',start)
ctes=helper[start:end].removeprefix('WITH ')
ctes=ctes.replace(":'raw_snapshot'::jsonb",'(SELECT raw_snapshot FROM raw_source)')
column_json=re.search(r'\$expected\$(.*?)\$expected\$::jsonb',(ROOT/'assert_schema.sql').read_text(),re.S).group(1)
sql="""-- Revision-2 SELECT-only TEST preflight. No launcher, fixture, SET or DDL.
-- Verify TEST ikmzxirldivefebgxzaa in SQL Editor URL, select role postgres.
WITH captured AS MATERIALIZED (
"""+diagnostic+"""\n), raw_source AS (
 SELECT (metadata_diagnostic->>'snapshot_text')::jsonb AS raw_snapshot FROM captured
), """+ctes.rstrip()+""", comparison AS (
 SELECT jsonb_set((SELECT raw_snapshot FROM raw_source),'{native,schemas}',(SELECT schemas FROM retained)) AS snapshot
)
SELECT jsonb_build_object('harness_revision',2,
 'expected_md5','90a71db3b16ed177b3455f61a59343b2',
 'comparison_md5',md5(comparison.snapshot::text),
 'matches_expected',md5(comparison.snapshot::text)='90a71db3b16ed177b3455f61a59343b2',
 'columns_match_expected',captured.metadata_diagnostic->'target_columns'=$columns$"""+column_json+"""$columns$::jsonb,
 'fixtures_absent',captured.metadata_diagnostic #> '{fixture_status,fixtures_absent}',
 'postgres_role_selected',captured.metadata_diagnostic #> '{operator_checks,postgres_role_selected}',
 'ignored_temporary_namespaces',coalesce((SELECT jsonb_agg(jsonb_build_object('oid',oid,'name',nspname,'owner',nspowner,'acl',nspacl) ORDER BY oid) FROM recognized_temporary),'[]'::jsonb),
 'raw_diagnostic',captured.metadata_diagnostic
) AS stage4_preflight_r2 FROM captured CROSS JOIN comparison;
"""
(ROOT/'preflight_r2_read_only.sql').write_text(sql,encoding='utf-8',newline='\n')
print('Prepared SELECT-only r2 preflight. NO SQL executed.')
