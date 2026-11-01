"""Offline regression checks only. Never connects to PostgreSQL or runs SQL."""
import ast
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent


def check():
    old = json.loads((ROOT.parents[1] / "inspection/mesh_inspection.json").read_text())
    manifest = json.loads((ROOT / "fidelity_manifest.json").read_text())
    preflight = json.loads((ROOT / "preflight_result.json").read_text(encoding="utf-8-sig"))
    raw = (ROOT / "bootstrap_test_only.sql").read_bytes()
    sql = raw.decode()
    assert hashlib.sha256(raw).hexdigest() == manifest["bootstrap_sha256"]
    assert hashlib.sha256((ROOT / "preflight_result.json").read_bytes()).hexdigest() == manifest["test_preflight_sha256"]
    assert b"\r\n" not in raw
    assert preflight["client_asserted_test_ref"] == manifest["allowed_test_ref"] == "ikmzxirldivefebgxzaa"
    assert manifest["blocked_production_ref"] == "khweikfvsnervfuswhon"
    blocks = dict(re.findall(r'CREATE TABLE public\."([a-z_]+)" \(\n(.*?)\n\);', sql, re.S))
    assert set(blocks) == {r["relname"] for r in old["01_inventory"]["inspection"]["tables"]}
    for table, body in blocks.items():
        actual = re.findall(r'^ "([a-z_]+)" ', body, re.M)
        expected = [r["column_name"] for r in old["02_columns"]["inspection"] if r["table_name"] == table]
        assert actual == expected, table
    constraints = old["03_constraints"]["inspection"]
    assert len(re.findall(r'^ALTER TABLE public\."\w+" ADD CONSTRAINT ', sql, re.M)) == 85
    for row in constraints:
        assert row["definition"] + ";" in sql, row["constraint_name"]
    backed = {(r["table_name"], r["constraint_name"]) for r in constraints if r["constraint_type"] in {"p", "u"}}
    for row in old["04_indexes"]["inspection"]:
        if (row["table_name"], row["index_name"]) not in backed:
            assert row["definition"] + ";" in sql
    assert len(backed) == 29 and len(re.findall(r'^CREATE (?:UNIQUE )?INDEX ', sql, re.M)) == 17
    for row in old["10_policies"]["inspection"]:
        assert 'CREATE POLICY "' + row["policy_name"] + '"' in sql
        if row["using_expression"]:
            assert row["using_expression"] in sql
    assert len(re.findall(r'^CREATE POLICY ', sql, re.M)) == 18
    assert len(re.findall(r'^CREATE TYPE ', sql, re.M)) == 2
    assert set(re.findall(r'^CREATE FUNCTION public\.([a-z_]+)', sql, re.M)) == {"handle_new_mesh_user", "is_mesh_member"}
    assert not re.search(r'^\s*(?:CREATE|ALTER|DROP)\s+(?:EVENT\s+TRIGGER|ROLE|SCHEMA|EXTENSION|TRIGGER)\b', sql, re.M | re.I)
    assert not re.search(r'^\s*ALTER FUNCTION\b', sql, re.M | re.I)
    assert not re.search(r'^\s*(?:GRANT|REVOKE)\b[^;]*\bON\s+SCHEMA\b', sql, re.M | re.I)
    assert not re.search(r'^\s*(?:GRANT|REVOKE)\b[^;]*\bON\s+FUNCTION\s+(?:public\.)?rls_auto_enable', sql, re.M | re.I)
    assert not re.search(r'^\s*(?:ALTER|DROP|TRUNCATE|INSERT INTO|UPDATE|DELETE FROM)\s+auth\.', sql, re.M | re.I)
    assert "ALTER DEFAULT PRIVILEGES" not in sql
    assert "CREATE OR REPLACE FUNCTION" not in sql
    assert "MAXVALUE 9223372036854775807" in sql and "9223372036854776000" not in sql
    assert sql.count("'auth_users_acl'") == 2
    assert sql.count("'auth_user_triggers'") == 2
    assert "NOT t.tgisinternal" in sql
    assert "IS DISTINCT FROM current_setting('mesh_test.native_snapshot')::jsonb" in sql
    assert "current_user<>'postgres' OR session_user<>'postgres'" in sql
    assert manifest["expected"]["custom_auth_user_trigger_created"] == 0
    assert manifest["expected"]["native_event_triggers_created_or_altered"] == 0
    assert not list((ROOT.parents[1] / "migrations").glob("*.sql"))
    for name in ["build_bootstrap.py", "validate_bootstrap.py"]:
        ast.parse((ROOT / name).read_text())
    # Lexical SQL checks only, not a PostgreSQL or PL/pgSQL compiler.
    index = 0
    stack = []
    while index < len(sql):
        if sql.startswith("--", index) or (sql[index] == "\\" and (index == 0 or sql[index - 1] == "\n")):
            end = sql.find("\n", index)
            index = len(sql) if end < 0 else end + 1
            continue
        if sql[index] in "'\"":
            quote = sql[index]
            index += 1
            while index < len(sql):
                if sql[index] == quote:
                    if index + 1 < len(sql) and sql[index + 1] == quote:
                        index += 2
                        continue
                    break
                index += 1
            assert index < len(sql), "Unterminated SQL quote"
        elif sql[index] == "$":
            match = re.match(r"\$[A-Za-z_][A-Za-z_0-9]*\$|\$\$", sql[index:])
            if match:
                tag = match.group()
                end = sql.find(tag, index + len(tag))
                assert end >= 0, "Unterminated dollar body"
                index = end + len(tag)
                continue
        elif sql[index] == "(":
            stack.append(index)
        elif sql[index] == ")":
            assert stack, "Unmatched closing parenthesis"
            stack.pop()
        index += 1
    assert not stack
    assert sql.rstrip().endswith("COMMIT;")
    print("PASS: source/hash/schema correspondence, 18 tables/165 columns/85 constraints/46 indexes/18 policies/2 enums.")
    print("PASS: only two new application functions; no native role/schema/function/event-trigger ACL or DDL changes emitted.")
    print("PASS: native snapshot invariants, preserved Auth noninternal triggers, corrected identity, target guards and lexical/Python AST checks.")
    print("NOT TESTED: PostgreSQL compilation, DDL permissions, runtime catalog equality or transaction execution. No SQL was executed.")


if __name__ == "__main__":
    check()
