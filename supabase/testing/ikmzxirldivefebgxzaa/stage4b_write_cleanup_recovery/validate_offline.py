"""Read-only static/dependency/integrity validation. Never invokes launcher or SQL."""
from pathlib import Path
import json
import re
from prepare_manifest import ROOT,ORIGINAL,HISTORY,original_files,sha

original_files()
pins=json.loads((ROOT/'pins.json').read_text())
assert pins['execution_authorized'] is False and pins['scope']=='read_only_cleanup_recovery'
assert json.loads((ROOT/'readiness.json').read_text())['database_execution_authorized'] is False
for name,digest in pins['files'].items():assert sha(ROOT/name)==digest,name
assert not (ROOT/'evidence').exists(),'No real recovery attempt may exist during preparation'
visited=set()
def visit(path):
    path=path.resolve()
    if path in visited:return
    visited.add(path);s=path.read_text()
    assert not re.search(r'^\s*(CREATE|ALTER|DROP|GRANT|REVOKE|INSERT|UPDATE|DELETE|TRUNCATE|COMMIT|COPY)\b',s,re.M|re.I),path
    assert not re.search(r'\\(?:connect|c|!|copy|quit|q)\b',s),path
    for name in re.findall(r'^\\ir\s+(\S+)',s,re.M):visit(path.parent/name)
visit(ORIGINAL/'cleanup_check.sql')
assert len(visited)==10
assert all(any((ROOT/name).resolve()==path for name in pins['files']) for path in visited)
assert 'BEGIN READ ONLY;' in (ORIGINAL/'cleanup_check.sql').read_text()
s=(ROOT/'Invoke-CleanupRecovery.ps1').read_text()
assert '[ValidateSet' not in s and '[string]$Action' not in s
assert 'cleanup_check.sql' in s and 'runtime.sql' not in s
assert s.index('foreach($pin')<s.index(". (Join-Path $root 'Recovery-Support.ps1')")<s.index('Assert-InteractiveRecoveryConsole')<s.index('[IO.Directory]::CreateDirectory')
assert 'default_transaction_read_only=on' in s and 'verify-full' in s
assert '-X -W ' in s and 'postgres.ikmzxirldivefebgxzaa' in s
assert 'PGPASSWORD' not in s and '.StandardInput.Write' not in s
assert "GetEnvironmentVariable" not in s and 'EnvironmentVariables.Remove' in s
assert '$info.RedirectStandardInput=$false' in s and '$info.CreateNoWindow=$false' in s
assert s.count('Invoke-RecoveryCapturedProcess -Info')==1
assert '[IO.FileMode]::CreateNew' in s and "'evidence/attempt_01'" in s
support=(ROOT/'Recovery-Support.ps1').read_text()
assert '.StandardError.ReadToEndAsync()' in support and '$code=$process.ExitCode' in support
assert support.index('if($ExitCode -ne 0)')<support.index('$records=@(')
for folder,manifest in [(ORIGINAL.parent/'stage4b_read','pins.json'),(ORIGINAL.parents[2]/'proposals/stage4b_write_phase1','preparation_pins.json')]:
    for name,digest in json.loads((folder/manifest).read_text())['files'].items():assert sha(folder/name)==digest
print('PASS: original 123 pins + six evidence hashes, recovery pins, 10 read-only SQL dependencies, cleanup-only/approval/console/transport assertions; no attempt created.')
