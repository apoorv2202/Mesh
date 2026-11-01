"""Pure tuple oracle mirroring assert_acl_exact; no SQL or database dependencies."""
def expected_acl(before, contract):
    rule=contract['remove']
    retained={tuple(t) for t in before if not (t[0]==rule['kind'] and t[1]==rule['object']
              and t[4] in rule['grantees'] and t[5] in rule['privileges'])}
    return retained | {tuple(t) for t in contract['add']}


def verify_acl(before, actual, contract):
    rows=[tuple(t) for t in actual]
    expected=expected_acl(before,contract)
    if len(rows)!=len(set(rows)) or set(rows)!=expected:
        raise ValueError('unexpected or missing ACL tuple')


def verify_memberships(before, actual):
    """Tuples: role, member, grantor, admin, inherit, set; old identity unchanged."""
    roles=('vader_writer_owner','vader_triage_owner','vader_ingest')
    expected=set(before)|{(r,'postgres','bootstrap:10',True,False,False) for r in roles}
    expected|={(r,'postgres','postgres',False,True,True) for r in roles}
    if len(actual)!=len(set(actual)) or set(actual)!=expected:
        raise ValueError('unexpected or missing role relationship')


def verify_restored(before, actual):
    if sorted(map(tuple,before))!=sorted(map(tuple,actual)):
        raise ValueError('rollback did not restore original tuples')
