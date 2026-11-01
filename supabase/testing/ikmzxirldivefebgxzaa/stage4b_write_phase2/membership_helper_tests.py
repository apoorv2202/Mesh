"""Offline regression for the one existing-helper ACL addition; never executes SQL."""
from pathlib import Path
import hashlib
import json
import re
import unittest
from acl_model import expected_acl, verify_acl, verify_restored

HERE=Path(__file__).resolve().parent
P=HERE.parents[2]/'proposals/stage4b_write_phase2'
IDENTITY='public.is_mesh_member(uuid, public.mesh_role[])'
ROW=('function',IDENTITY,'','postgres','vader_triage_owner','EXECUTE',False)

class HelperTests(unittest.TestCase):
    def setUp(self):
        self.contract=json.loads((P/'acl_contract.json').read_text())
        self.before=[('function',IDENTITY,'','postgres',r,'EXECUTE',False) for r in ('postgres','authenticated')]
        self.good=expected_acl(self.before,self.contract)
    def test_exact_single_helper_addition(self):
        self.assertEqual([tuple(r) for r in self.contract['add'] if r[1].startswith('public.is_mesh_member')],[ROW])
        verify_acl(self.before,self.good,self.contract)
    def test_missing_helper_execute_rejected(self):
        with self.assertRaises(ValueError):verify_acl(self.before,self.good-{ROW},self.contract)
    def test_broader_grantees_rejected(self):
        for role in ('PUBLIC','anon','service_role','vader_writer_owner','vader_ingest'):
            bad=list(ROW);bad[4]=role
            with self.subTest(role=role),self.assertRaises(ValueError):verify_acl(self.before,self.good|{tuple(bad)},self.contract)
    def test_wrong_grantor_signature_and_grant_option(self):
        for index,value in [(1,'public.is_mesh_member(uuid)'),(3,'vader_triage_owner'),(6,True)]:
            bad=list(ROW);bad[index]=value
            with self.subTest(field=index),self.assertRaises(ValueError):verify_acl(self.before,(self.good-{ROW})|{tuple(bad)},self.contract)
    def test_existing_helper_rights_cannot_be_removed(self):
        for row in self.before:
            with self.assertRaises(ValueError):verify_acl(self.before,self.good-{row},self.contract)
    def test_rollback_requires_original_helper_acl(self):
        verify_restored(self.before,self.before)
        with self.assertRaises(ValueError):verify_restored(self.before,self.before+[ROW])
    def test_grant_order_and_unchanged_helper_definition(self):
        for name in ('04_human_triage.sql','04_human_triage.body.psql'):
            s=(P/name).read_text()
            grant='GRANT EXECUTE ON FUNCTION public.is_mesh_member(uuid,public.mesh_role[]) TO vader_triage_owner;'
            self.assertEqual(s.count(grant),1)
            self.assertLess(s.index('CREATE ROLE vader_triage_owner'),s.index(grant))
            self.assertLess(s.index(grant),s.index('DO $member_usage$'))
            self.assertNotRegex(s,r'(?:CREATE(?: OR REPLACE)?|ALTER|DROP) FUNCTION public\.is_mesh_member')
    def test_exact_metadata_exception_and_oracle_capture(self):
        s=(HERE/'assert_delta.sql').read_text()
        self.assertIn("category='functions' AND (oldrow->>'oid')::oid='public.is_mesh_member(uuid,public.mesh_role[])'::regprocedure",s)
        self.assertIn("oldrow-'acl' IS DISTINCT FROM newrow-'acl'",s)
        sql=(HERE/'assert_acl_exact.sql').read_text()
        for text in ('helper_before AS','helper_actual AS','mesh_write.acl_extended_before','grantor','is_grantable'):
            self.assertIn(text,sql)
    def test_historical_sources_and_all_evidence_unchanged(self):
        before=json.loads((P/'review_archive/membership_fix_before.json').read_text())
        repo=HERE.parents[3]
        protected={n:h for n,h in before.items() if '/evidence/' in n or '/stage4b_write_cleanup_recovery/' in n}
        self.assertGreaterEqual(len(protected),17)
        for name,digest in protected.items():
            self.assertEqual(hashlib.sha256((repo/name).read_bytes()).hexdigest(),digest,name)
        original=json.loads((P/'review_archive/pins.before_membership_helper_fix.json').read_text())['files']
        oldhash=original['capture_acl.sql']
        self.assertEqual(hashlib.sha256((HERE/'capture_acl.sql').read_bytes()).hexdigest(),oldhash)

if __name__=='__main__':unittest.main(verbosity=2)
