"""Explicit LOCAL preparation only. Pins original evidence without modifying it."""
from pathlib import Path
import hashlib
import json
import os
import sys

ROOT=Path(__file__).resolve().parent
ORIGINAL=ROOT.parent/'stage4b_write_phase2'
REVIEWED='9ce235e2887aea69bc0772c09ff8e646412cb845ce97cfd8df96e6d52976df68'
HISTORY={
 'runtime.txt':'a0bf348ce7a2a602e52da9b9385d02937b9b40d109e2e32bbbc461148234d53a',
 'runtime.stderr.txt':'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
 'runtime.receipt.json':'3b2eedc1cdfe3c417907909373c563c4c4ed0002b725c86747c46811ef1244a1',
 'cleanup_check.txt':'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
 'cleanup_check.stderr.txt':'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
 'cleanup_check.receipt.json':'da13a35090d634a258acea0dc25ab5bc7af200022051d0d7392dc46f9b930321'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return os.path.relpath(p,ROOT).replace('\\','/')
def original_files():
    if sha(ORIGINAL/'pins.json')!=REVIEWED:raise ValueError('Original reviewed manifest changed')
    files={ORIGINAL/'pins.json'}
    for name,digest in json.loads((ORIGINAL/'pins.json').read_text())['files'].items():
        p=(ORIGINAL/name).resolve()
        if sha(p)!=digest:raise ValueError('Original pinned artifact changed: '+name)
        files.add(p)
    for name,digest in HISTORY.items():
        p=ORIGINAL/'evidence'/name
        if sha(p)!=digest:raise ValueError('Historical failed evidence changed: '+name)
        files.add(p)
    return files

if __name__=='__main__':
    if sys.argv[1:]!=['--prepare-local-manifest']:raise ValueError('Explicit local preparation flag required')
    readiness=json.loads((ROOT/'readiness.json').read_text())
    if readiness['database_execution_authorized'] is not False:raise ValueError('Execution not permitted')
    files=original_files()
    inventory={'modified_original_files':[],'new_local_files':sorted(p.name for p in ROOT.iterdir() if p.is_file() and p.name!='pins.json')+['pins.json','change_inventory.json'],
               'original_manifest_sha256':REVIEWED,'original_evidence_sha256':HISTORY}
    inventory['new_local_files']=sorted(set(inventory['new_local_files']))
    (ROOT/'change_inventory.json').write_text(json.dumps(inventory,indent=2)+'\n',encoding='utf8')
    files.update(p.resolve() for p in ROOT.iterdir() if p.is_file() and p.name!='pins.json')
    manifest={'test_ref':'ikmzxirldivefebgxzaa','scope':'read_only_cleanup_recovery','revision':'cleanup_recovery_v1',
      'execution_authorized':False,'files':{rel(p):sha(p) for p in sorted(files)}}
    (ROOT/'pins.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf8')
    print('Recovery preparation pins:',len(files),'SHA-256:',sha(ROOT/'pins.json'))
    print('All six historical evidence hashes and original 123 source pins preserved. No attempt created.')
