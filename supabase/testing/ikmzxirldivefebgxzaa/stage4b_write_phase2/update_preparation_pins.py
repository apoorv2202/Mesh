"""Explicit local-only preparation repin. Historical artifacts must still match."""
from pathlib import Path
import hashlib
import json
import os
import sys
from gate_state import load_preparation

HERE=Path(__file__).resolve().parent
PROPOSALS=HERE.parents[2]/'proposals/stage4b_write_phase2'

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def rel(path):return os.path.relpath(path,HERE).replace('\\','/')

if __name__=='__main__':
    assert sys.argv[1:]==['--refresh-reviewed-local-only'],'Explicit local preparation flag required'
    print('Local preparation state:',load_preparation(HERE))
    archive=PROPOSALS/'review_archive/pins.before_blocker_corrections.json'
    previous=json.loads(archive.read_text())
    changed=[];files=set()
    for name,oldhash in previous['files'].items():
        path=(HERE/name).resolve();files.add(path)
        actual=digest(path)
        if actual!=oldhash:
            assert path.is_relative_to(HERE) or path.is_relative_to(PROPOSALS),'Historical artifact changed: '+name
            changed.append({'path':name,'before_sha256':oldhash,'after_sha256':actual})
    for folder in (HERE,PROPOSALS):
        for path in folder.rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts and 'evidence' not in path.relative_to(folder).parts and path.suffix!='.pyc':
                if path!=HERE/'pins.json':files.add(path.resolve())
    report=PROPOSALS/'changed_preparation_files.json';files.add(report)
    original={(HERE/name).resolve() for name in previous['files']}
    report.write_text(json.dumps({'date':'2026-10-31','historical_files_changed':False,
      'modified':sorted(changed,key=lambda x:x['path']),
      'added':[rel(p) for p in sorted(files-original)]},indent=2)+'\n',encoding='utf8')
    pins={'test_ref':'ikmzxirldivefebgxzaa','revision':'write_phase2_membership_helper_v7',
          'execution_authorized':False,'files':{rel(p):digest(p) for p in sorted(files)}}
    (HERE/'pins.json').write_text(json.dumps(pins,indent=2)+'\n',encoding='utf8')
    print(f'Pinned {len(files)} artifacts; {len(changed)} existing local preparation files changed; historical hashes preserved.')
    print('Manifest SHA-256:',digest(HERE/'pins.json'))
