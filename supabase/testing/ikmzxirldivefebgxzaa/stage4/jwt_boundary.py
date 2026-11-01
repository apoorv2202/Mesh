"""Optional, explicitly approved real-JWT READ ONLY HTTP tests. No Auth writes."""
import argparse
import base64
import getpass
import hashlib
import json
from pathlib import Path
import ssl
import urllib.request
import urllib.error
import uuid

ROOT=Path(__file__).resolve().parent
REF='ikmzxirldivefebgxzaa'
BASE='https://'+REF+'.supabase.co'

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        return None

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--approve-stage4',choices=[REF],required=True)
    args=parser.parse_args()
    pins=json.loads((ROOT/'pins.json').read_text())
    if pins['test_ref']!=REF:raise RuntimeError('Wrong TEST pins')
    for name,digest in pins['files'].items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=digest:
            raise RuntimeError('Reviewed artifact drift')
    # Only metadata receipts. Never write tokens, keys, request/response bodies.
    folder=ROOT/'evidence';folder.mkdir(exist_ok=True)
    path=folder/'jwt_boundary.json'
    with path.open('x',encoding='utf-8') as out:out.write('{"status":"reserved_no_retry"}\n')
    records=[]
    passed=False
    try:
        key=getpass.getpass('TEST publishable API key (hidden): ')
        if not key.startswith('sb_publishable_'):
            raise RuntimeError('Only a TEST publishable key is accepted; no service/secret key')
        ids=[str(uuid.UUID(input('Synthetic TEST user '+name+' UUID: ').strip())) for name in ['A','B']]
        if ids[0]==ids[1]:raise RuntimeError('Distinct users required')
        tokens=[getpass.getpass('Fresh TEST user '+name+' access JWT (hidden): ') for name in ['A','B']]
        for i,token in enumerate(tokens):
            parts=token.split('.')
            if len(parts)!=3:raise RuntimeError('JWT format invalid')
            hints=json.loads(base64.urlsafe_b64decode(parts[1]+'='*(-len(parts[1])%4)))
            if hints.get('iss')!=BASE+'/auth/v1' or hints.get('sub')!=ids[i] or hints.get('role')!='authenticated':
                raise RuntimeError('Token does not claim the expected TEST issuer/user/role')
        # Decoded hints are only a routing guard. /auth/v1/user verifies authenticity.
        opener=urllib.request.build_opener(NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        def request(path,token=None,extra=None):
            headers={'apikey':key}
            if token:headers['Authorization']='Bearer '+token
            if extra:headers.update(extra)
            req=urllib.request.Request(BASE+path,headers=headers,method='GET')
            try:
                with opener.open(req,timeout=15) as response:
                    return response.status,json.loads(response.read(65536))
            except urllib.error.HTTPError as error:
                # Never persist server bodies/headers; they can contain identity data.
                return error.code,None
        def check(name,condition,status):
            records.append({'case':name,'passed':bool(condition),'http_status':status})
            if not condition:raise RuntimeError('Boundary assertion failed')
        for i,token in enumerate(tokens):
            status,body=request('/auth/v1/user',token)
            check('signed_user_'+str(i),status==200 and isinstance(body,dict) and body.get('id')==ids[i],status)
        def encoded(obj):return base64.urlsafe_b64encode(json.dumps(obj,separators=(',',':')).encode()).decode().rstrip('=')
        pieces=tokens[0].split('.')
        if len(pieces)!=3:raise RuntimeError('JWT format invalid')
        payload=json.loads(base64.urlsafe_b64decode(pieces[1]+'='*(-len(pieces[1])%4)))
        payload.update(sub=ids[1],role='service_role',organization_id='44444444-4444-4444-8444-000000000002')
        tampered='.'.join([pieces[0],encoded(payload),pieces[2]])
        status,_=request('/auth/v1/user',tampered)
        check('tampered_sub_role_org_rejected',status in [401,403],status)
        unsigned=encoded({'alg':'none','typ':'JWT'})+'.'+encoded(payload)+'.'
        status,_=request('/auth/v1/user',unsigned)
        check('unsigned_jwt_rejected',status in [401,403],status)
        status,body=request('/auth/v1/user',tokens[0],{'X-Organization-Id':payload['organization_id'],'X-User-Id':ids[1]})
        check('spoof_headers_do_not_replace_identity',status==200 and isinstance(body,dict) and body.get('id')==ids[0],status)
        for table in ['security_events','security_findings','security_incidents','incident_events','security_risk_scores']:
            for who,token in [('anon',None),('A',tokens[0]),('B',tokens[1])]:
                for suffix in ['000000000001','000000000002']:
                    status,_=request('/rest/v1/'+table+'?select=organization_id&organization_id=eq.44444444-4444-4444-8444-'+suffix+'&limit=1',token)
                    check('acl_denial_'+table+'_'+who+'_'+suffix,status in ([401,403] if who=='anon' else [403]),status)
        passed=True
    finally:
        path.write_text(json.dumps({'test_ref':REF,'passed':passed,'cases':records,
          'writes_performed':False,'rls_row_filtering':'NOT_PROVEN_ACL_DENIAL'},indent=2)+'\n',encoding='utf-8')
    print('PASS: real JWT boundary and existing HTTP ACL denials. No RLS filtering claim.')

if __name__=='__main__':
    try:main()
    except Exception:
        # No raw exception, URL headers, JWT, credentials or response bodies.
        print('STOP: test failed/blocked; inspect sanitized receipt. Do not retry automatically.')
        raise SystemExit(1)
