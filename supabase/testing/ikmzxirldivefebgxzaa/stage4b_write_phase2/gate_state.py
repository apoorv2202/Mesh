"""Local preparation state validation only. This module cannot execute a harness.

Eligibility is distinct from a future invocation's explicit approval and reviewed
hash. Persisted database-execution authorization is forbidden in this workflow.
"""
from pathlib import Path
import hashlib
import json
import re

TEST='ikmzxirldivefebgxzaa'
SCOPE='rollback-only DDL and human SQL-role tier; no machine LOGIN or real JWT proof'
RECORD='../../../proposals/stage4b_write_phase2/LIFECYCLE_APPROVAL.md'
FIELDS={'authorizable','lifecycle_contracts_approved','approved_contract_sha256',
        'approval_record','database_execution_authorized','scope','blockers'}

def validate_state(ready,manifest,contract_sha256):
    if not isinstance(ready,dict) or set(ready)!=FIELDS:
        raise ValueError('Missing or unexpected readiness field')
    if type(ready['authorizable']) is not bool:
        raise ValueError('Eligibility must be a literal boolean')
    if ready['database_execution_authorized'] is not False:
        raise ValueError('Database execution must remain unauthorized')
    if ready['lifecycle_contracts_approved'] is not True:
        raise ValueError('Lifecycle approval required for this preparation revision')
    if ready['scope']!=SCOPE or ready['approval_record']!=RECORD:
        raise ValueError('Unexpected scope or approval record')
    value=ready['approved_contract_sha256']
    if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{64}',value) or value!=contract_sha256:
        raise ValueError('Approved contract hash mismatch')
    if not isinstance(ready['blockers'],list) or not ready['blockers'] or any(not isinstance(x,str) or not x.strip() for x in ready['blockers']):
        raise ValueError('Explicit remaining execution prerequisites required')
    if not isinstance(manifest,dict) or set(manifest)!={'test_ref','revision','execution_authorized','files'}:
        raise ValueError('Unexpected preparation manifest structure')
    if manifest['test_ref']!=TEST or manifest['execution_authorized'] is not False:
        raise ValueError('Only TEST preparation without execution authorization is supported')
    if not isinstance(manifest['revision'],str) or not manifest['revision'] or not isinstance(manifest['files'],dict):
        raise ValueError('Invalid preparation manifest')
    return 'eligible_not_authorized' if ready['authorizable'] else 'sealed_not_authorized'

def load_preparation(root):
    root=Path(root)
    ready=json.loads((root/'execution_readiness.json').read_text())
    manifest=json.loads((root/'pins.json').read_text())
    contract=root/'../../../proposals/stage4b_write_phase2/CONTRACTS.md'
    state=validate_state(ready,manifest,hashlib.sha256(contract.read_bytes()).hexdigest())
    if not (root/RECORD).is_file():raise ValueError('Approval record absent')
    return state
