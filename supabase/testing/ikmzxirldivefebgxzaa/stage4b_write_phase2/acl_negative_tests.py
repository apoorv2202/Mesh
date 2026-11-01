"""Intentional privilege mutations in memory only; never execute database grants."""
from pathlib import Path
import json
import unittest
from acl_model import expected_acl,verify_acl,verify_memberships,verify_restored

ROOT=Path(__file__).resolve().parent
CONTRACT=json.loads((ROOT.parents[2]/'proposals/stage4b_write_phase2/acl_contract.json').read_text())


class ACLTests(unittest.TestCase):
    def setUp(self):
        self.before=[('schema','extensions','','postgres','anon','USAGE',False),
         ('table','public.audit_logs','','postgres','anon','TRUNCATE',False),
         ('table','public.audit_logs','','postgres','authenticated','SELECT',False)]
        self.good=expected_acl(self.before,CONTRACT)
    def reject(self,row):
        with self.assertRaises(ValueError):verify_acl(self.before,self.good|{row},CONTRACT)
    def test_exact_approved_delta(self):verify_acl(self.before,self.good,CONTRACT)
    def test_column_select_without_table_select(self):
        for role in ('service_role','anon','authenticated','PUBLIC'):
            with self.subTest(role=role):self.reject(('column','public.security_events','details','postgres',role,'SELECT',False))
    def test_unexpected_table_select(self):self.reject(('table','public.security_events','','postgres','service_role','SELECT',False))
    def test_unexpected_private_table_select(self):self.reject(('table','vader_private.receipts','','postgres','authenticated','SELECT',False))
    def test_schema_public_usage_or_create(self):
        for role,priv in [('PUBLIC','USAGE'),('vader_writer_owner','CREATE')]:
            with self.subTest(role=role):self.reject(('schema','extensions','','postgres',role,priv,False))
    def test_private_schema_usage(self):self.reject(('schema','vader_private','','postgres','service_role','USAGE',False))
    def test_grant_options_all_kinds(self):
        for kind in ('table','column','schema','function','sequence'):
            original=next(x for x in CONTRACT['add'] if x[0]==kind)
            bad=tuple(original[:-1]+[True])
            with self.subTest(kind=kind),self.assertRaises(ValueError):verify_acl(self.before,(self.good-{tuple(original)})|{bad},CONTRACT)
    def test_function_unexpected_grantee(self):
        original=next(x for x in CONTRACT['add'] if x[0]=='function')
        bad=list(original);bad[4]='anon'
        self.reject(tuple(bad))
    def test_grantor_change(self):
        row=next(iter(self.good));bad=list(row);bad[3]='service_role'
        with self.assertRaises(ValueError):verify_acl(self.before,(self.good-{row})|{tuple(bad)},CONTRACT)
    def test_old_select_removal_is_denied(self):
        row=('table','public.audit_logs','','postgres','authenticated','SELECT',False)
        with self.assertRaises(ValueError):verify_acl(self.before,self.good-{row},CONTRACT)
    def test_missing_dependency_usage(self):
        row=('schema','extensions','','postgres','vader_writer_owner','USAGE',False)
        with self.assertRaises(ValueError):verify_acl(self.before,self.good-{row},CONTRACT)
    def test_exact_creator_edges(self):
        before={('authenticated','authenticator','bootstrap:10',False,False,True)}
        roles=('vader_writer_owner','vader_triage_owner','vader_ingest')
        new={(r,'postgres','bootstrap:10',True,False,False) for r in roles}
        new|={(r,'postgres','postgres',False,True,True) for r in roles}
        verify_memberships(before,before|new)
        for row in [('vader_writer_owner','authenticated','bootstrap:10',True,True,True),
                    ('vader_writer_owner','postgres','postgres',True,True,True),
                    ('vader_writer_owner','postgres','bootstrap:10',True,True,False)]:
            with self.subTest(edge=row),self.assertRaises(ValueError):verify_memberships(before,before|new|{row})
        with self.assertRaises(ValueError):verify_memberships(before,new)
    def test_rollback_restores_acl_and_membership(self):
        verify_restored(self.before,self.before)
        with self.assertRaises(ValueError):verify_restored(self.before,self.good)
        before=[('authenticated','authenticator','bootstrap:10',False,False,True)]
        verify_restored(before,before)
        with self.assertRaises(ValueError):verify_restored(before,before+[('vader_ingest','postgres','bootstrap:10',True,True,True)])
    def test_duplicate_tuple_rejected(self):
        rows=list(self.good)
        with self.assertRaises(ValueError):verify_acl(self.before,rows+[rows[0]],CONTRACT)


if __name__=='__main__':unittest.main(verbosity=2)
