"""Fail-closed parser for this proposal's SQL subset, not a PostgreSQL compiler.

Ownership keys include schema, function name and canonical IN argument types.
Unsupported identifiers/modes/default expressions must be reviewed explicitly.
Importing this module performs no I/O and never generates files.
"""
import re

IDENT=r'[A-Za-z_][A-Za-z_0-9]*'
QUALIFIED=rf'({IDENT})\s*\.\s*({IDENT})'
ALIASES={'int':'integer','int4':'integer','int8':'bigint','bool':'boolean',
         'timestamptz':'timestamp with time zone','timestamp':'timestamp without time zone',
         'float8':'double precision','varchar':'character varying'}
MULTI={'timestamp with time zone','timestamp without time zone','double precision',
       'character varying','time with time zone','time without time zone','bit varying'}
CREATE=re.compile(rf'CREATE\s+FUNCTION\s+{QUALIFIED}\s*\(([^()]*)\)\s*RETURNS\s+({IDENT})\s+LANGUAGE\s+({IDENT})(.*?)\bAS\s+\$(?P<tag>{IDENT})\$(?P<body>.*?)\$(?P=tag)\$\s*',re.I|re.S)
TRANSFER=re.compile(rf'ALTER\s+FUNCTION\s+{QUALIFIED}\s*\(([^()]*)\)\s+OWNER\s+TO\s+({IDENT})\s*',re.I|re.S)

def statements(sql):
    result=[];buf=[];i=0
    while i<len(sql):
        if sql.startswith('--',i):
            end=sql.find('\n',i);i=len(sql) if end<0 else end;buf.append(' ');continue
        if sql.startswith('/*',i):
            depth=1;i+=2
            while depth and i<len(sql):
                if sql.startswith('/*',i):depth+=1;i+=2
                elif sql.startswith('*/',i):depth-=1;i+=2
                else:i+=1
            if depth:raise ValueError('Unterminated SQL comment')
            buf.append(' ');continue
        if sql[i] in "'\"":
            quote=sql[i];start=i;i+=1
            while i<len(sql):
                if sql[i]==quote:
                    i+=1
                    if i<len(sql) and sql[i]==quote:i+=1;continue
                    break
                i+=1
            else:raise ValueError('Unterminated SQL quote')
            buf.append(sql[start:i]);continue
        dollar=re.match(r'\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$',sql[i:])
        if dollar:
            tag=dollar.group();end=sql.find(tag,i+len(tag))
            if end<0:raise ValueError('Unterminated SQL dollar body')
            end+=len(tag);buf.append(sql[i:end]);i=end;continue
        if sql[i]==';':
            text=''.join(buf).strip()
            if text:result.append(text)
            buf=[];i+=1;continue
        buf.append(sql[i]);i+=1
    if ''.join(buf).strip():raise ValueError('Unterminated top-level SQL statement')
    return result

def canonical_type(value):
    value=re.sub(r'\s+',' ',value.strip()).lower()
    value=re.sub(r'\s*\.\s*','.',value)
    value=re.sub(r'\s*\[\s*\]', '[]', value)
    suffix=''
    while value.endswith('[]'):suffix+='[]';value=value[:-2]
    if value not in MULTI and not re.fullmatch(rf'{IDENT}(?:\.{IDENT})?',value):
        raise ValueError('Unsupported argument type: '+value)
    return ALIASES.get(value,value)+suffix

def arguments(raw, creation=False):
    if not raw.strip():return [],[],[]
    names=[];types=[];canonical=[]
    for arg in raw.split(','):
        text=arg.strip()
        if not text:raise ValueError('Empty argument between commas')
        if re.search(r'\bDEFAULT\b',text,re.I):
            if not creation or not re.search(r'\s+DEFAULT\s+NULL\s*$',text,re.I):raise ValueError('Unsupported argument default')
            text=re.sub(r'\s+DEFAULT\s+NULL\s*$','',text,flags=re.I)
        if re.match(r'^(OUT|INOUT|VARIADIC)\b',text,re.I):raise ValueError('Unsupported argument mode')
        text=re.sub(r'^IN\s+','',text,flags=re.I)
        if creation:
            m=re.fullmatch(rf'({IDENT})\s+(.+)',text,re.S)
            if not m:raise ValueError('Named IN arguments required in CREATE FUNCTION')
            name,typ=m.groups()
        else:
            name=None;typ=text
            try:canonical_type(typ)
            except ValueError:
                m=re.fullmatch(rf'({IDENT})\s+(.+)',text,re.S)
                if not m:raise
                name,typ=m.groups()
        names.append(name.lower() if name else None);types.append(typ.strip());canonical.append(canonical_type(typ))
    return names,types,canonical

def signature(schema,name,types):return (schema.lower(),name.lower(),tuple(canonical_type(t) for t in types))

def parse_sources(sources, creator_owned, allowed_owners):
    if any(owner not in allowed_owners for owner in creator_owned.values()):raise ValueError('Unapproved creator-owner default')
    functions=[];by_key={};transfers=[]
    for source in sources:
        for statement in statements(source):
            if re.match(r'^CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\b',statement,re.I):
                m=CREATE.fullmatch(statement)
                if not m:raise ValueError('Unrecognized CREATE FUNCTION statement')
                schema,name,args,returns,language,options,tag,body=m.groups()
                names,types,_=arguments(args,creation=True);key=signature(schema,name,types)
                if key in by_key:raise ValueError('Duplicate function signature: '+str(key))
                spec=dict(schema=schema.lower(),name=name.lower(),arg_names=names,arg_types=types,
                  returns=returns.lower(),language=language.lower(),definer=bool(re.search(r'\bSECURITY\s+DEFINER\b',options,re.I)),
                  strict=bool(re.search(r'\bSTRICT\b',options,re.I)),
                  volatility='i' if re.search(r'\bIMMUTABLE\b',options,re.I) else 's' if re.search(r'\bSTABLE\b',options,re.I) else 'v',body=body)
                by_key[key]=spec;functions.append(spec)
            elif re.match(r'^ALTER\s+(FUNCTION|ROUTINE|PROCEDURE)\b',statement,re.I):
                m=TRANSFER.fullmatch(statement)
                if not m:raise ValueError('Unrecognized ownership/ALTER FUNCTION statement')
                schema,name,args,owner=m.groups();owner=owner.lower()
                _,types,_=arguments(args);key=signature(schema,name,types)
                if key not in by_key:raise ValueError('Transfer does not match an earlier CREATE signature: '+str(key))
                if owner not in allowed_owners:raise ValueError('Unapproved function owner: '+owner)
                by_key[key]['owner']=owner
                transfers.append(dict(schema=key[0],name=key[1],arg_types=list(key[2]),owner=owner))
    if set(creator_owned)-set(by_key):raise ValueError('Expected creator-owned helper missing')
    for key,spec in by_key.items():
        if 'owner' not in spec:
            if key not in creator_owned:raise ValueError('Missing explicit ownership transfer: '+str(key))
            spec['owner']=creator_owned[key]
        elif key in creator_owned and spec['owner']!=creator_owned[key]:
            raise ValueError('Protected creator-owned helper changed owner')
    return functions,transfers
