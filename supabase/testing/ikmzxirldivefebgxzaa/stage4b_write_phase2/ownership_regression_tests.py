"""Ownership parser regressions; memory/text only, no SQL execution or generators."""
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parents[2]/'proposals/stage4b_write_phase2'))
from ownership_parser import parse_sources,signature,statements
from verify_ownership_contracts import verify

OWNERS={'postgres','writer_one','writer_two'}
def create(name='public.f',args=''):
    return f'CREATE FUNCTION {name}({args}) RETURNS text LANGUAGE sql AS $fn$ SELECT \'value\' $fn$;\n'
def transfer(name='public.f',args='',owner='writer_one'):
    return f'ALTER FUNCTION {name}({args}) OWNER TO {owner};\n'
def parse(sql,defaults=None):return parse_sources([sql],defaults or {},OWNERS)


class OwnershipTests(unittest.TestCase):
    def test_parameterless_transfer(self):
        specs,history=parse(create()+transfer())
        self.assertEqual(specs[0]['owner'],'writer_one');self.assertEqual(history[0]['arg_types'],[])
    def test_argument_transfer(self):
        specs,_=parse(create(args='tenant uuid, payload jsonb')+transfer(args='uuid,jsonb'))
        self.assertEqual(specs[0]['owner'],'writer_one')
    def test_overloads_are_signature_specific(self):
        sql=create()+create(args='value text')+create(args='value uuid')
        sql+=transfer(args='uuid',owner='writer_two')+transfer()+transfer(args='text')
        specs,_=parse(sql)
        self.assertEqual([(s['arg_types'],s['owner']) for s in specs],[([], 'writer_one'),(['text'],'writer_one'),(['uuid'],'writer_two')])
    def test_multiple_transfers_preserve_history_and_final_owner(self):
        specs,history=parse(create()+transfer()+transfer(owner='writer_two'))
        self.assertEqual(specs[0]['owner'],'writer_two')
        self.assertEqual([x['owner'] for x in history],['writer_one','writer_two'])
    def test_missing_transfer_never_silently_defaults(self):
        with self.assertRaises(ValueError):parse(create())
    def test_only_explicit_creator_helper_defaults(self):
        key=signature('public','f',[])
        specs,_=parse(create(),{key:'postgres'});self.assertEqual(specs[0]['owner'],'postgres')
        with self.assertRaises(ValueError):parse(create()+create('public.other'),{key:'postgres'})
    def test_protected_helper_cannot_change_owner(self):
        with self.assertRaises(ValueError):parse(create()+transfer(),{signature('public','f',[]):'postgres'})
    def test_unknown_target_or_overload_is_rejected(self):
        for sql in (create()+transfer('public.other'),create()+transfer(args='uuid'),transfer()+create()):
            with self.subTest(sql=sql),self.assertRaises(ValueError):parse(sql)
    def test_unrecognized_transfer_statements_are_rejected(self):
        for stmt in ('ALTER FUNCTION public.f OWNER TO writer_one;',
                     'ALTER FUNCTION public.f() OWNER TO;',
                     'ALTER ROUTINE public.f() OWNER TO writer_one;',
                     'ALTER FUNCTION public.f() SET search_path=public;',
                     'ALTER FUNCTION "public"."f"() OWNER TO writer_one;',
                     'ALTER FUNCTION public.f() OWNER TO CURRENT_USER;',
                     'ALTER FUNCTION public.f(uuid,,text) OWNER TO writer_one;'):
            with self.subTest(stmt=stmt),self.assertRaises(ValueError):parse(create()+stmt)
    def test_unknown_owner_is_rejected(self):
        with self.assertRaises(ValueError):parse(create()+transfer(owner='service_role'))
    def test_comment_or_body_text_is_not_a_transfer(self):
        sql="-- ALTER FUNCTION public.f() OWNER TO service_role;\n"+create()+transfer()
        sql+="DO $x$ BEGIN RAISE NOTICE 'ALTER FUNCTION public.f() OWNER TO service_role;'; END $x$;"
        specs,history=parse(sql);self.assertEqual(specs[0]['owner'],'writer_one');self.assertEqual(len(history),1)
    def test_alias_and_named_in_signature(self):
        specs,_=parse(create(args='IN at timestamptz DEFAULT NULL')+transfer(args='at timestamp with time zone'))
        self.assertEqual(specs[0]['owner'],'writer_one')
    def test_duplicate_create_is_rejected(self):
        with self.assertRaises(ValueError):parse(create()+create()+transfer())
    def test_same_name_in_different_schemas(self):
        specs,_=parse(create('one.f')+create('two.f')+transfer('two.f',owner='writer_two')+transfer('one.f'))
        self.assertEqual([(s['schema'],s['owner']) for s in specs],[('one','writer_one'),('two','writer_two')])
    def test_unapproved_creator_default_is_rejected(self):
        with self.assertRaises(ValueError):parse(create(),{signature('public','f',[]):'service_role'})
    def test_malformed_sql_is_rejected(self):
        for sql in (create()+transfer().rstrip(';\n'),create()+"/* unterminated",create()+"DO $x$ unclosed"):
            with self.subTest(sql=sql),self.assertRaises(ValueError):parse(sql)
    def test_actual_sql_object_acl_and_assertions_agree(self):
        self.assertEqual(verify(),(13,16))


if __name__=='__main__':unittest.main(verbosity=2)
