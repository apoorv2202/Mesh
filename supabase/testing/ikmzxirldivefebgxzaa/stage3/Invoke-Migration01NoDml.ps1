# Separate launcher: only local Validate, one ApplyNoDml, or read-only VerifyNoDml.
[CmdletBinding()]
param(
 [ValidateSet('Validate','ApplyNoDml','VerifyNoDml')][string]$Action='Validate',
 [switch]$ApproveNoDml
)
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$pins=Get-Content -LiteralPath (Join-Path $root 'pins_no_dml.json') -Raw | ConvertFrom-Json
foreach ($pin in $pins.files.PSObject.Properties) {
 if ((Get-FileHash -LiteralPath (Join-Path $root $pin.Name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pin.Value) { throw "Reviewed artifact changed: $($pin.Name). STOP." }
}
if ($pins.test_ref -cne 'ikmzxirldivefebgxzaa') { throw 'TEST reference mismatch' }
$proposal=Join-Path $root '../../../proposals/01_vader_security_hardening.sql'
if ((Get-FileHash -LiteralPath $proposal -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pins.proposal_sha256) { throw 'Proposal changed' }
$bootstrap=Get-Content -LiteralPath (Join-Path $root '../bootstrap_execution_result.json') -Raw | ConvertFrom-Json
if ($bootstrap.target -cne $pins.test_ref -or !$bootstrap.bootstrap_commit_acknowledged -or !$bootstrap.structural_verification_passed) { throw 'Bootstrap evidence invalid' }
$evidence=Join-Path $root 'evidence'
function Require-Pass([string]$Name) {
 $r=Get-Content -LiteralPath (Join-Path $evidence "$Name.receipt.json") -Raw | ConvertFrom-Json
 if (!$r.passed -or $r.proposal_sha256 -cne $pins.proposal_sha256 -or $r.test_ref -cne $pins.test_ref) { throw "Invalid prerequisite: $Name" }
 if ($Name -eq 'apply_no_dml' -and $r.variant_sha256 -cne $pins.files.'apply_no_dml.sql') { throw 'Apply evidence belongs to a different variant' }
 if ((Get-FileHash -LiteralPath (Join-Path $evidence "$Name.txt") -Algorithm SHA256).Hash.ToLowerInvariant() -cne $r.output_sha256) { throw 'Prerequisite output changed' }
}
Require-Pass 'baseline'; Require-Pass 'gate'; Require-Pass 'rollback'
if ($Action -eq 'Validate') { Write-Host 'PASS: local original/variant/evidence pins. NO SQL executed.'; return }
if (!$ApproveNoDml) { throw 'Explicit new-variant execution authorization and -ApproveNoDml required' }
$phase=if ($Action -eq 'ApplyNoDml') {'apply_no_dml'} else {'verify_no_dml'}
$sql=if ($Action -eq 'ApplyNoDml') {'apply_no_dml.sql'} else {'verify.sql'}
$receipt=Join-Path $evidence "$phase.receipt.json"
$output=Join-Path $evidence "$phase.txt"
if ((Test-Path -LiteralPath $receipt) -or (Test-Path -LiteralPath $output)) { throw 'Phase already reserved/executed. No retry.' }
if ((Test-Path -LiteralPath (Join-Path $evidence 'apply.receipt.json')) -or (Test-Path -LiteralPath (Join-Path $evidence 'apply.txt'))) { throw 'Original Apply attempt evidence exists; stop to resolve outcome before variant' }
if ($Action -eq 'VerifyNoDml') { Require-Pass 'apply_no_dml' }
$baseline=Get-Content -LiteralPath (Join-Path $evidence 'baseline.txt') -Raw | ConvertFrom-Json
if ($baseline.snapshot_md5 -cnotmatch '^[a-f0-9]{32}$') { throw 'Baseline digest missing' }
$psql='C:\Program Files\PostgreSQL\18\bin\psql.exe'
$ca='C:\Users\APOORV\Downloads\prod-ca-2021.crt'
if (!(Test-Path -LiteralPath $psql -PathType Leaf)) { throw 'Reviewed psql missing' }
if ((Get-FileHash -LiteralPath $ca -Algorithm SHA256).Hash.ToLowerInvariant() -cne '700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7') { throw 'Reviewed CA changed' }
$cert=New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ca)
$basic=$cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' }
if (!$basic -or !$basic.CertificateAuthority -or $cert.HasPrivateKey -or $cert.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or $cert.NotAfter.ToUniversalTime() -lt [DateTime]::UtcNow) { throw 'Invalid CA' }
$names=@('PGHOST','PGHOSTADDR','PGUSER','PGPORT','PGDATABASE','PGSERVICE','PGSERVICEFILE','PGPASSWORD','PGPASSFILE',
 'PGOPTIONS','PGSSLMODE','PGSSLROOTCERT','PGAPPNAME','PGCONNECT_TIMEOUT','PGSSLCERT','PGSSLKEY','PGSSLCRL','PGSSLCRLDIR','PGREQUIRESSL')
$saved=@{}
$stream=[IO.File]::Open($receipt,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
$stream.Dispose()
$passed=$false
try {
 foreach ($name in $names) { $saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process'); [Environment]::SetEnvironmentVariable($name,$null,'Process') }
 $env:PGHOST='aws-0-eu-west-1.pooler.supabase.com'
 $env:PGUSER='postgres.ikmzxirldivefebgxzaa'; $env:PGPORT='5432'; $env:PGDATABASE='postgres'
 $env:PGSSLMODE='verify-full'; $env:PGSSLROOTCERT=$ca; $env:PGCONNECT_TIMEOUT='10'
 $env:PGAPPNAME="mesh-vader-stage3-$phase"
 $ro=if ($Action -eq 'VerifyNoDml') {'on'} else {'off'}
 $env:PGOPTIONS="-c default_transaction_read_only=$ro -c statement_timeout=60000 -c lock_timeout=5000 -c idle_in_transaction_session_timeout=60000"
 $psqlArgs=@('-X','-W','-q','-A','-t','--host',$env:PGHOST,'--port','5432','--username',$env:PGUSER,'--dbname','postgres',
 '--set','ON_ERROR_STOP=1','--set','vader_test_ref=ikmzxirldivefebgxzaa','--set','stage3_approved=ikmzxirldivefebgxzaa',
 '--file',(Join-Path $root $sql),'--output',$output)
 if ($Action -eq 'ApplyNoDml') { $psqlArgs+=@('--set',"expected_baseline_md5=$($baseline.snapshot_md5)") }
 # Interactive console owns stdin; only metadata query output goes to evidence.
 & $psql @psqlArgs
 if ($LASTEXITCODE -ne 0) { throw "Phase failed (exit $LASTEXITCODE). STOP; no retry." }
 $lines=@(Get-Content -LiteralPath $output | Where-Object { $_.StartsWith('{') })
 if ($lines.Count -ne 1) { throw 'Missing/ambiguous evidence' }
 $data=$lines[0] | ConvertFrom-Json
 if ($Action -eq 'ApplyNoDml') {
  if (!(Select-String -LiteralPath $output -Pattern '^MIGRATION01_COMMIT_ACKNOWLEDGED$' -Quiet)) { throw 'COMMIT acknowledgement missing; outcome unknown, no retry' }
 } else {
  $apply=Get-Content -LiteralPath (Join-Path $evidence 'apply_no_dml.txt') | Where-Object { $_.StartsWith('{') } | ConvertFrom-Json
  function Normalize($v) {
   if ($null -eq $v) { return 'null' }
   if ($v -is [System.Management.Automation.PSCustomObject]) {
    return '{'+(($v.PSObject.Properties | Sort-Object Name | ForEach-Object { ($_.Name | ConvertTo-Json -Compress)+':'+(Normalize $_.Value) }) -join ',')+'}'
   }
   if ($v -is [System.Array]) { return '['+(($v | ForEach-Object { Normalize $_ }) -join ',')+']' }
   return ($v | ConvertTo-Json -Compress)
  }
  if ((Normalize $data) -cne (Normalize $apply.after)) { throw 'Post-commit drift from asserted state' }
 }
 $passed=$true
 Write-Host "PASS: $Action. STOP; no automatic next phase."
} finally {
 foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name,$saved[$name],'Process') }
 $outHash=if (Test-Path -LiteralPath $output) {(Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant()} else {$null}
 @{test_ref=$pins.test_ref;phase=$phase;passed=$passed;proposal_sha256=$pins.proposal_sha256;
 variant_sha256=$pins.files.'apply_no_dml.sql';output_sha256=$outHash;
 recorded_at_utc=[DateTime]::UtcNow.ToString('o');dml_probes_executed=$false;rls_tests_executed=$false;migration02_executed=$false} |
 ConvertTo-Json | Set-Content -LiteralPath $receipt -Encoding UTF8
}
