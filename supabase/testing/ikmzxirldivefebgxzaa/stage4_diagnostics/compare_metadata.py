"""Compare a user-supplied TEST export locally. No database or network access."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parent
PROJECT=ROOT.parent

def unwrap(value):
    if isinstance(value,str):return unwrap(json.loads(value))
    if isinstance(value,list):
        if len(value)!=1:raise ValueError('Exactly one diagnostic row required')
        return unwrap(value[0])
    if isinstance(value,dict) and 'metadata_diagnostic' in value:return unwrap(value['metadata_diagnostic'])
    if isinstance(value,dict) and 'actual_snapshot_md5' in value:return value
    raise ValueError('Expected complete diagnostic JSON, not a screenshot or partial snapshot')

def field_changes(before,after,path=''):
    if isinstance(before,dict) and isinstance(after,dict):
        result=[]
        for key in sorted(before.keys()|after.keys()):
            newpath=path+'/'+str(key)
            if key not in before:result.append({'path':newpath,'added':after[key]})
            elif key not in after:result.append({'path':newpath,'removed':before[key]})
            else:result.extend(field_changes(before[key],after[key],newpath))
        return result
    if before!=after:return [{'path':path,'before':before,'after':after}]
    return []

def compare_rows(before,after,keys):
    if not isinstance(before,list) or not isinstance(after,list):return {'changes':field_changes(before,after)}
    def index(rows):
        result={}
        for row in rows:
            key=json.dumps([row.get(k) for k in keys],sort_keys=True)
            if key in result:raise ValueError('Nonunique comparison key: '+key)
            result[key]=row
        return result
    old=index(before);new=index(after)
    return {'before_count':len(before),'after_count':len(after),
      'array_order_only':before!=after and old==new,
      'added':[new[k] for k in sorted(new.keys()-old.keys())],
      'removed':[old[k] for k in sorted(old.keys()-new.keys())],
      'changed':[{'key':json.loads(k),'fields':field_changes(old[k],new[k])} for k in sorted(old.keys()&new.keys()) if old[k]!=new[k]]}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('export',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    manifest=json.loads((ROOT/'diagnostic_manifest.json').read_text())
    path=PROJECT/'stage3/evidence/verify_no_dml.txt'
    raw=path.read_bytes()
    assert hashlib.sha256(raw).hexdigest()==manifest['baseline_sha256']
    expected_text=raw.decode('utf-8-sig').strip()
    assert hashlib.md5(expected_text.encode('utf-8')).hexdigest()==manifest['expected_baseline_md5']
    baseline=json.loads(expected_text)
    diagnostic=unwrap(json.loads(args.export.read_text(encoding='utf-8-sig')))
    assert diagnostic['client_asserted_test_ref']=='ikmzxirldivefebgxzaa'
    assert diagnostic['operator_checks']['postgres_role_selected']
    text=diagnostic['snapshot_text']
    computed=hashlib.md5(text.encode('utf-8')).hexdigest()
    assert computed==diagnostic['actual_snapshot_md5'],'Export altered/truncated or non-UTF8 server encoding: investigate; do not compare silently'
    actual=json.loads(text)
    expected_columns=json.loads((PROJECT/'stage4/verified_schema.json').read_text())['02_columns']
    keys=['table_name','column_name','ordinal_position','postgres_type','nullable','identity_kind','default_or_generation_expression']
    expected_columns=[{k:r[k] for k in keys} for r in expected_columns]
    categories={
      'grants_effective':compare_rows(baseline['effective'],actual['effective'],['rolname','relname','privilege']),
      'grants_target_acls':compare_rows(baseline['target_acls'],actual['target_acls'],['table']),
      'grants_column_acls':{'changes':field_changes(baseline['column_acls'],actual['column_acls'])},
      'columns':compare_rows(expected_columns,diagnostic['target_columns'],['table_name','column_name']),
    }
    keymap={'roles':['oid'],'memberships':['roleid','member','grantor'],'schemas':['oid'],
      'functions':['oid'],'events':['oid'],'defaults':['oid'],'relations':['oid'],
      'sequences':['seqrelid'],'policies':['oid'],'constraints':['oid'],
      'indexes':['indexrelid'],'triggers':['oid'],'target_rls':['table']}
    for category,keys in keymap.items():
        categories[category]=compare_rows(baseline['native'][category],actual['native'][category],keys)
    identical=baseline==actual
    hash_equal=computed==manifest['expected_baseline_md5']
    if identical and hash_equal:classification='CURRENT_SNAPSHOT_MATCHES; earlier failed snapshot unavailable'
    elif identical:classification='TEXT_REPRESENTATION_DIFFERS; parsed snapshot identical'
    else:classification='CAPTURED_VALUES_DIFFER; inspect category details; session effects vs real drift not yet resolved'
    result={'expected_baseline_md5':manifest['expected_baseline_md5'],'actual_snapshot_md5':computed,
      'hash_matches':hash_equal,'parsed_snapshot_matches':identical,'classification':classification,
      'session_settings':diagnostic['session_settings'],'operator_checks':diagnostic['operator_checks'],
      'effective_schemas':diagnostic['effective_schemas'],'fixture_status':diagnostic['fixture_status'],
      'object_labels':diagnostic['object_labels'],'categories':categories,
      'limits':['Snapshot query hashes routine definitions/settings, not recoverable function source.',
       'Column comparison covers five target tables, against the earlier full schema capture.',
       'Original failed-run actual snapshot/session settings were not captured.',
       'SQL Editor session may differ from original psql session. No automatic rebaseline or session normalization.'],
      'stage4_decision':'NO-GO_PENDING_REVIEW'}
    with args.output.open('x',encoding='utf-8') as out:json.dump(result,out,indent=2);out.write('\n')
    print(json.dumps({k:result[k] for k in ['expected_baseline_md5','actual_snapshot_md5','hash_matches','classification','stage4_decision']},indent=2))
    print('Fixture status:',json.dumps(result['fixture_status']))
    for category,diff in categories.items():
        print(category,':',len(diff.get('added',[])),'added,',len(diff.get('removed',[])),'removed,',len(diff.get('changed',diff.get('changes',[]))),'changed; array-order-only',diff.get('array_order_only',False))

if __name__=='__main__':main()
