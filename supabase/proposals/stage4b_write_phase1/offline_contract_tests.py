"""Memory-only security contract model. NO SQL, network or subprocess execution.

This tests intended behavior, not the PostgreSQL implementation. Actual locking,
RLS, EXECUTE, grants, transaction semantics and authentication remain unverified.
"""
import copy
import threading
import unittest


class Contract:
    def __init__(self):
        self.lock = threading.RLock()
        self.members = {'alice': ('A', 'security_team', 'active'),
                        'bob': ('B', 'security_team', 'active')}
        self.rows, self.receipts, self.audits = {}, {}, []

    def write(self, principal, tenant, key, body, *, human=False, fail_audit=False):
        with self.lock:
            before = copy.deepcopy((self.rows, self.receipts, self.audits))
            try:
                if human:
                    if self.members.get(principal) != (tenant, 'security_team', 'active'):
                        raise PermissionError('membership')
                    allowed = {'id', 'status', 'expected', 'assignee'}
                else:
                    if principal != 'backend_' + tenant:
                        raise PermissionError('binding')
                    allowed = {'id', 'reference', 'revision'}
                if set(body) - allowed:
                    raise ValueError('restricted column')
                receipt = (principal, tenant, key)
                if receipt in self.receipts:
                    if self.receipts[receipt] != body:
                        raise ValueError('replay conflict')
                    return 'replay'
                target = (tenant, body['id'])
                if human:
                    if target not in self.rows:
                        raise PermissionError('target')
                    if body.get('assignee') is not None and self.members.get(body['assignee']) != (tenant, 'security_team', 'active'):
                        raise PermissionError('assignee')
                    if body['expected'] != self.rows[target]:
                        raise RuntimeError('stale')
                    self.rows[target] = body['status']
                else:
                    if 'reference' in body and (tenant, body['reference']) not in self.rows:
                        raise PermissionError('reference')
                    if target in self.rows:
                        raise ValueError('immutable identity')
                    self.rows[target] = 'open'
                if fail_audit:
                    raise RuntimeError('audit failure')
                self.audits.append((tenant, body['id']))
                self.receipts[receipt] = copy.deepcopy(body)
                return 'fresh'
            except Exception:
                self.rows, self.receipts, self.audits = before
                raise


class Tests(unittest.TestCase):
    def setUp(self):
        self.c = Contract()

    def seed(self):
        self.c.write('backend_A', 'A', 'seed', {'id': 'finding'})

    def test_tenant_machine_and_atomic_audit(self):
        self.seed()
        self.assertEqual(self.c.rows, {('A', 'finding'): 'open'})
        self.assertEqual(len(self.c.audits), 1)

    def test_cross_tenant_machine(self):
        with self.assertRaises(PermissionError):
            self.c.write('backend_A', 'B', 'x', {'id': 'x'})

    def test_restricted_columns(self):
        for column in ('organization_id', 'actor_user_id', 'asset_id', 'assigned_to', 'status', 'delete'):
            with self.subTest(column=column), self.assertRaises(ValueError):
                self.c.write('backend_A', 'A', 'x', {'id': 'x', column: 'spoof'})

    def test_invalid_and_cross_tenant_reference(self):
        self.seed()
        for tenant, reference in [('A', 'missing'), ('B', 'finding')]:
            with self.subTest(tenant=tenant), self.assertRaises(PermissionError):
                self.c.write('backend_' + tenant, tenant, 'x', {'id': 'x', 'reference': reference})

    def test_replay_and_changed_payload(self):
        self.seed()
        self.assertEqual(self.c.write('backend_A', 'A', 'seed', {'id': 'finding'}), 'replay')
        self.assertEqual(len(self.c.audits), 1)
        with self.assertRaises(ValueError):
            self.c.write('backend_A', 'A', 'seed', {'id': 'other'})

    def test_immutable_risk_revisions(self):
        for revision in ('r1', 'r2'):
            self.c.write('backend_A', 'A', revision, {'id': revision, 'revision': revision})
        self.assertEqual(len(self.c.rows), 2)
        with self.assertRaises(ValueError):
            self.c.write('backend_A', 'A', 'different-key', {'id': 'r1', 'revision': 'changed'})

    def test_roles_status_and_missing_identity(self):
        self.seed()
        for role in ('owner', 'hr', 'senior_developer', 'junior_developer', 'security_team'):
            for status in ('active', 'suspended', 'offboarded'):
                self.c.members['candidate'] = ('A', role, status)
                if (role, status) == ('security_team', 'active'):
                    continue
                with self.subTest(role=role, status=status), self.assertRaises(PermissionError):
                    self.c.write('candidate', 'A', 't', {'id': 'finding', 'expected': 'open', 'status': 'investigating'}, human=True)
        with self.assertRaises(PermissionError):
            self.c.write(None, 'A', 't', {'id': 'finding'}, human=True)

    def test_human_cross_tenant_and_assignee(self):
        self.seed()
        with self.assertRaises(PermissionError):
            self.c.write('bob', 'B', 't', {'id': 'finding', 'expected': 'open', 'status': 'investigating'}, human=True)
        with self.assertRaises(PermissionError):
            self.c.write('alice', 'A', 't', {'id': 'finding', 'expected': 'open', 'status': 'investigating', 'assignee': 'bob'}, human=True)

    def test_concurrent_updates_single_winner(self):
        self.seed()
        outcomes = []
        def update(key):
            try:
                self.c.write('alice', 'A', key, {'id': 'finding', 'expected': 'open', 'status': 'investigating'}, human=True)
                outcomes.append('ok')
            except RuntimeError:
                outcomes.append('stale')
        threads = [threading.Thread(target=update, args=(str(n),)) for n in range(2)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertCountEqual(outcomes, ['ok', 'stale'])

    def test_offboarding_rejects_even_replay(self):
        self.seed()
        body = {'id': 'finding', 'expected': 'open', 'status': 'investigating'}
        self.c.write('alice', 'A', 't', body, human=True)
        self.c.members['alice'] = ('A', 'security_team', 'offboarded')
        with self.assertRaises(PermissionError):
            self.c.write('alice', 'A', 't', body, human=True)

    def test_machine_audit_failure_rolls_back_everything(self):
        with self.assertRaises(RuntimeError):
            self.c.write('backend_A', 'A', 'x', {'id': 'x'}, fail_audit=True)
        self.assertEqual((self.c.rows, self.c.receipts, self.c.audits), ({}, {}, []))

    def test_human_audit_failure_restores_state_and_receipt(self):
        self.seed()
        before = copy.deepcopy((self.c.rows, self.c.receipts, self.c.audits))
        with self.assertRaises(RuntimeError):
            self.c.write('alice', 'A', 't', {'id': 'finding', 'expected': 'open', 'status': 'investigating'}, human=True, fail_audit=True)
        self.assertEqual((self.c.rows, self.c.receipts, self.c.audits), before)


if __name__ == '__main__':
    unittest.main(verbosity=2)
