"""In-memory preparation-state tests; no runtime/cleanup/SQL/network execution."""
import copy
import json
from pathlib import Path
import unittest
from gate_state import validate_state

ROOT=Path(__file__).resolve().parent

class GateTests(unittest.TestCase):
    def setUp(self):
        self.ready=json.loads((ROOT/'execution_readiness.json').read_text())
        self.manifest=json.loads((ROOT/'pins.json').read_text())
        self.sha=self.ready['approved_contract_sha256']
    def check(self):return validate_state(self.ready,self.manifest,self.sha)
    def test_eligible_is_not_execution_authorization(self):
        self.ready['authorizable']=True
        self.assertEqual(self.check(),'eligible_not_authorized')
        self.assertIs(self.ready['database_execution_authorized'],False)
        self.assertIs(self.manifest['execution_authorized'],False)
    def test_sealed_state_remains_valid(self):
        self.ready['authorizable']=False
        self.assertEqual(self.check(),'sealed_not_authorized')
    def test_database_authorization_true_is_rejected(self):
        self.ready['database_execution_authorized']=True
        with self.assertRaises(ValueError):self.check()
    def test_manifest_authorization_true_is_rejected(self):
        self.manifest['execution_authorized']=True
        with self.assertRaises(ValueError):self.check()
    def test_invalid_boolean_types_are_rejected(self):
        for field in ('authorizable','database_execution_authorized','lifecycle_contracts_approved'):
            for value in ('false','true',0,1,None):
                original=copy.deepcopy(self.ready);self.ready[field]=value
                with self.subTest(field=field,value=value),self.assertRaises(ValueError):self.check()
                self.ready=original
    def test_unknown_readiness_fields_are_rejected(self):
        for field in ('execution_authorized','skip_approval','allow_production','override_hash'):
            self.ready[field]=False
            with self.subTest(field=field),self.assertRaises(ValueError):self.check()
            del self.ready[field]
    def test_missing_readiness_fields_are_rejected(self):
        for field in list(self.ready):
            original=self.ready.pop(field)
            with self.subTest(field=field),self.assertRaises(ValueError):self.check()
            self.ready[field]=original
    def test_stale_contract_hash_is_rejected(self):
        self.ready['approved_contract_sha256']='0'*64
        with self.assertRaises(ValueError):self.check()
    def test_unapproved_lifecycle_is_rejected(self):
        self.ready['lifecycle_contracts_approved']=False
        with self.assertRaises(ValueError):self.check()
    def test_wrong_scope_or_approval_record_is_rejected(self):
        for key in ('scope','approval_record'):
            original=self.ready[key];self.ready[key]='unexpected'
            with self.subTest(key=key),self.assertRaises(ValueError):self.check()
            self.ready[key]=original
    def test_wrong_project_is_rejected(self):
        self.manifest['test_ref']='khweikfvsnervfuswhon'
        with self.assertRaises(ValueError):self.check()
    def test_unknown_manifest_field_is_rejected(self):
        self.manifest['skip_approval']=True
        with self.assertRaises(ValueError):self.check()
    def test_missing_execution_prerequisites_are_rejected(self):
        self.ready['blockers']=[]
        with self.assertRaises(ValueError):self.check()

if __name__=='__main__':unittest.main(verbosity=2)
