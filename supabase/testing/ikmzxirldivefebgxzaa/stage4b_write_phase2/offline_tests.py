"""Independent memory-only contract and receipt tests; never executes harness/SQL."""
import copy
import importlib.util
import json
from pathlib import Path
import threading
import unittest

FINDING = {'open': {'investigating','false_positive'}, 'investigating': {'remediating','false_positive'},
           'remediating': {'resolved'}, 'resolved': {'investigating'}, 'false_positive': {'investigating'}}
INCIDENT = {'detected': {'triaged','false_positive'}, 'triaged': {'investigating','false_positive'},
            'investigating': {'contained','false_positive'}, 'contained': {'remediating'},
            'remediating': {'recovering'}, 'recovering': {'resolved'}, 'resolved': {'triaged'}, 'false_positive': {'triaged'}}


class Model:
    def __init__(self):
        self.lock=threading.RLock()
        self.members={'a':('A','security_team','active'),'b':('B','security_team','active')}
        self.state={'status':'open','revision':0}
        self.audits=[];self.receipts={}

    def offboard(self, actor):
        with self.lock:
            tenant,role,_=self.members[actor]
            self.members[actor]=(tenant,role,'offboarded')

    def triage(self, actor, tenant, key, payload, *, fault=False, entered=None, release=None):
        with self.lock:
            before=copy.deepcopy((self.state,self.audits,self.receipts))
            try:
                if self.members.get(actor)!=(tenant,'security_team','active') or tenant!='A':
                    raise PermissionError('scope')
                if set(payload)!={'status','revision'}: raise ValueError('restricted fields')
                if key in self.receipts:
                    if self.receipts[key][0]!=payload: raise ValueError('replay conflict')
                    return self.receipts[key][1]
                if payload['revision']!=self.state['revision']: raise RuntimeError('stale')
                if payload['status'] not in FINDING.get(self.state['status'],set()): raise ValueError('transition')
                if entered is not None:
                    entered.set()
                    if not release.wait(2): raise RuntimeError('test synchronization timeout')
                self.state={'status':payload['status'],'revision':self.state['revision']+1}
                if fault: raise RuntimeError('audit failure')
                self.audits.append(key);self.receipts[key]=(copy.deepcopy(payload),copy.deepcopy(self.state))
                return copy.deepcopy(self.state)
            except Exception:
                self.state,self.audits,self.receipts=before
                raise


def evidence_pass(exit_code, records, acks):
    if exit_code!=0: return False  # Preserve native failure before parsing success records.
    results=[r for r in records if r.get('record_type')=='stage4b_write_result']
    return len(results)==1 and results[0].get('passed') is True and acks==1


class ContractTests(unittest.TestCase):
    def setUp(self): self.m=Model()
    def write(self,status='investigating',revision=0,key='k',**kw):
        return self.m.triage('a','A',key,{'status':status,'revision':revision},**kw)
    def test_closure_reopen_revision_prevents_ABA(self):
        for n,status in enumerate(('investigating','remediating','resolved','investigating')):
            self.write(status,n,str(n))
        self.assertEqual(self.m.state,{'status':'investigating','revision':4})
        with self.assertRaises(RuntimeError): self.write('remediating',1,'old-token')
    def test_false_positive_and_reopen(self):
        self.write('false_positive');self.write('investigating',1,'reopen')
        self.assertEqual(self.m.state['revision'],2)
    def test_invalid_transitions_and_accepted_risk(self):
        for status in ('resolved','accepted_risk','contained'):
            with self.subTest(status=status),self.assertRaises(ValueError): self.write(status)
        self.assertEqual(INCIDENT['resolved'],{'triaged'})
        self.assertNotIn('resolved',INCIDENT['detected'])
    def test_cross_tenant_and_restricted_fields(self):
        with self.assertRaises(PermissionError): self.m.triage('b','B','x',{'status':'investigating','revision':0})
        with self.assertRaises(ValueError): self.m.triage('a','A','x',{'status':'investigating','revision':0,'organization_id':'B'})
    def test_replay_conflict_and_no_second_audit(self):
        result=self.write();self.assertEqual(self.write(),result)
        self.assertEqual(self.m.audits,['k'])
        with self.assertRaises(ValueError): self.write('remediating')
    def test_offboarding_before_authorization(self):
        self.m.offboard('a')
        with self.assertRaises(PermissionError): self.write()
    def test_offboarding_after_authorization_waits(self):
        entered=threading.Event();release=threading.Event();offboard_done=threading.Event();errors=[]
        def writer():
            try:self.write(entered=entered,release=release)
            except Exception as error:errors.append(error)
        def offboard():self.m.offboard('a');offboard_done.set()
        first=threading.Thread(target=writer);first.start()
        self.assertTrue(entered.wait(2))
        second=threading.Thread(target=offboard);second.start()
        self.assertFalse(offboard_done.wait(.02));release.set()
        first.join(2);second.join(2)
        self.assertFalse(first.is_alive());self.assertFalse(second.is_alive());self.assertEqual(errors,[])
        self.assertEqual(self.m.state['revision'],1)
        with self.assertRaises(PermissionError): self.write()  # Even exact replay denied.
    def test_audit_failure_rolls_back_revision_receipt_domain(self):
        original=copy.deepcopy((self.m.state,self.m.audits,self.m.receipts))
        with self.assertRaises(RuntimeError): self.write(fault=True)
        self.assertEqual((self.m.state,self.m.audits,self.m.receipts),original)
    def test_error_receipt_cannot_be_masked_by_success_json(self):
        record={'record_type':'stage4b_write_result','passed':True}
        self.assertFalse(evidence_pass(3,[record],1))
        self.assertFalse(evidence_pass(0,[record,record],1))
        self.assertFalse(evidence_pass(0,[record],0))
        self.assertFalse(evidence_pass(0,[record],2))
        self.assertTrue(evidence_pass(0,[record],1))


if __name__=='__main__': unittest.main(verbosity=2)
