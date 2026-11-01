# Preparation only. No action executes without explicit approval and a named phase.
[CmdletBinding()]
param(
 [ValidateSet('Validate','Baseline','Gate','Rollback','Apply','Verify','Dml','Rls')][string]$Action='Validate',
 [switch]$ApproveStage3,
 [string]$UserA,
 [string]$UserB
)
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$pins=Get-Content -LiteralPath (Join-Path $root 'pins.json') -Raw | ConvertFrom-Json
foreach ($pin in $pins.files.PSObject.Properties) {
 if ((Get-FileHash -LiteralPath (Join-Path $root $pin.Name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pin.Value) { throw "Reviewed file changed: $($pin.Name)" }
}
$proposal=Join-Path $root '../../../proposals/01_vader_security_hardening.sql'
if ((Get-FileHash -LiteralPath $proposal -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pins.proposal_sha256) { throw 'Proposal changed; STOP for review' }
if ($pins.test_ref -cne 'ikmzxirldivefebgxzaa') { throw 'TEST pin failed' }
$status=Get-Content -LiteralPath (Join-Path $root '../bootstrap_execution_result.json') -Raw | ConvertFrom-Json
if ($status.target -cne $pins.test_ref -or !$status.bootstrap_commit_acknowledged -or !$status.structural_verification_passed) { throw 'Successful TEST bootstrap evidence missing' }
if ($Action -eq 'Validate') { Write-Host 'Local pins validated. NO SQL executed.'; return }
if (!$ApproveStage3) { throw 'Explicit Stage 3 execution authorization and -ApproveStage3 required' }
$phase=$Action.ToLowerInvariant()
$evidence=Join-Path $root 'evidence'
$null=New-Item -ItemType Directory -Path $evidence -Force
$receipt=Join-Path $evidence "$phase.receipt.json"
$output=Join-Path $evidence "$phase.txt"
if ((Test-Path -LiteralPath $receipt) -or (Test-Path -LiteralPath $output)) { throw 'Existing evidence: do not overwrite/retry automatically' }
function Require-Pass([string]$Name) {
 $r=Get-Content -LiteralPath (Join-Path $evidence "$Name.receipt.json") -Raw | ConvertFrom-Json
 if (!$r.passed -or $r.proposal_sha256 -cne $pins.proposal_sha256 -or $r.test_ref -cne $pins.test_ref) { throw "Missing reviewed prerequisite: $Name" }
 if ((Get-FileHash -LiteralPath (Join-Path $evidence "$Name.txt") -Algorithm SHA256).Hash.ToLowerInvariant() -cne $r.output_sha256) { throw 'Prerequisite evidence changed' }
}
if ($Action -eq 'Gate') { Require-Pass 'baseline' }
if ($Action -eq 'Rollback') { Require-Pass 'baseline'; Require-Pass 'gate' }
if ($Action -eq 'Apply') { Require-Pass 'baseline'; Require-Pass 'gate'; Require-Pass 'rollback' }
if ($Action -eq 'Verify') { Require-Pass 'apply' }
if ($Action -eq 'Rls') {
 $a=[guid]::Parse($UserA); $b=[guid]::Parse($UserB)
 if ($a -eq $b -or $a -eq [guid]::Empty -or $b -eq [guid]::Empty) { throw 'Two distinct nonzero synthetic TEST Auth UUIDs required' }
}
$psql='C:\Program Files\PostgreSQL\18\bin\psql.exe'
$ca='C:\Users\APOORV\Downloads\prod-ca-2021.crt'
if ((Get-FileHash -LiteralPath $ca -Algorithm SHA256).Hash.ToLowerInvariant() -cne '700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7') { throw 'Reviewed TLS CA changed' }
$cert=New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ca)
if ($cert.HasPrivateKey -or $cert.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or $cert.NotAfter.ToUniversalTime() -lt [DateTime]::UtcNow) { throw 'Invalid CA dates/key' }
$names=@('PGHOST','PGHOSTADDR','PGUSER','PGPORT','PGDATABASE','PGSERVICE','PGSERVICEFILE','PGPASSWORD','PGPASSFILE',
 'PGOPTIONS','PGSSLMODE','PGSSLROOTCERT','PGAPPNAME','PGCONNECT_TIMEOUT','PGSSLCERT','PGSSLKEY','PGSSLCRL','PGSSLCRLDIR','PGREQUIRESSL')
$saved=@{}
# Reserve each named phase once. Any error/unknown commit requires review, no retry.
$stream=[IO.File]::Open($receipt,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
$stream.Dispose()
$passed=$false
try {
 foreach ($name in $names) { $saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process'); [Environment]::SetEnvironmentVariable($name,$null,'Process') }
 $env:PGHOST='aws-0-eu-west-1.pooler.supabase.com'
 $env:PGUSER='postgres.ikmzxirldivefebgxzaa'; $env:PGPORT='5432'; $env:PGDATABASE='postgres'
 $env:PGSSLMODE='verify-full'; $env:PGSSLROOTCERT=$ca; $env:PGCONNECT_TIMEOUT='10'
 $env:PGAPPNAME="mesh-vader-stage3-$phase"
 $ro=if ($Action -in @('Baseline','Verify')) {'on'} else {'off'}
 $env:PGOPTIONS="-c default_transaction_read_only=$ro -c statement_timeout=60000 -c lock_timeout=5000 -c idle_in_transaction_session_timeout=60000"
 $argsList=@('-X','-W','-q','-A','-t','--host',$env:PGHOST,'--port','5432','--username',$env:PGUSER,'--dbname','postgres',
 '--set','ON_ERROR_STOP=1','--set','vader_test_ref=ikmzxirldivefebgxzaa','--set','stage3_approved=ikmzxirldivefebgxzaa',
 '--file',(Join-Path $root "$phase.sql"),'--output',$output)
 if ($Action -eq 'Rls') { $argsList+=@('--set',"user_a=$a",'--set',"user_b=$b") }
 if ($Action -in @('Rollback','Apply')) {
  $baseline=Get-Content -LiteralPath (Join-Path $evidence 'baseline.txt') -Raw | ConvertFrom-Json
  if ($baseline.snapshot_md5 -cnotmatch '^[a-f0-9]{32}$') { throw 'Baseline snapshot digest missing' }
  $argsList+=@('--set',"expected_baseline_md5=$($baseline.snapshot_md5)")
 }
 & $psql @argsList
 if ($LASTEXITCODE -ne 0) { throw "Phase failed (exit $LASTEXITCODE). STOP; no retry or automatic recovery." }
 # Verify the one-row JSON result and explicit post-COMMIT acknowledgement.
 $lines=@(Get-Content -LiteralPath $output | Where-Object { $_.StartsWith('{') })
 if ($lines.Count -ne 1) { throw 'Missing/ambiguous metadata evidence' }
 $data=$lines[0] | ConvertFrom-Json
 if ($Action -eq 'Apply' -and !(Select-String -LiteralPath $output -Pattern '^MIGRATION01_COMMIT_ACKNOWLEDGED$' -Quiet)) { throw 'COMMIT acknowledgement missing; outcome unknown, STOP' }
 if ($Action -eq 'Rollback' -and !$data.restored) { throw 'Rollback restoration not proven' }
 if ($Action -in @('Gate','Dml','Rls') -and !$data.passed) { throw 'Probe result missing' }
 if ($Action -eq 'Verify') {
  $apply=Get-Content -LiteralPath (Join-Path $evidence 'apply.txt') | Where-Object { $_.StartsWith('{') } | ConvertFrom-Json
  # Compare JSON semantically with a local helper, not formatting/property order.
  function Normalize($v) {
   if ($null -eq $v) { return 'null' }
   if ($v -is [System.Management.Automation.PSCustomObject]) {
    return '{'+(($v.PSObject.Properties | Sort-Object Name | ForEach-Object { ($_.Name | ConvertTo-Json -Compress)+':'+(Normalize $_.Value) }) -join ',')+'}'
   }
   if ($v -is [System.Array]) { return '['+(($v | ForEach-Object { Normalize $_ }) -join ',')+']' }
   return ($v | ConvertTo-Json -Compress)
  }
  if ((Normalize $data) -cne (Normalize $apply.after)) { throw 'Post-commit catalog drift from asserted precommit state' }
 }
 $passed=$true
 Write-Host "PASS: $Action. STOP; no automatic next phase."
} finally {
 foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name,$saved[$name],'Process') }
 $outHash=if (Test-Path -LiteralPath $output) {(Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant()} else {$null}
 @{test_ref=$pins.test_ref;phase=$phase;passed=$passed;proposal_sha256=$pins.proposal_sha256;
 output_sha256=$outHash;recorded_at_utc=[DateTime]::UtcNow.ToString('o');migration02_executed=$false} |
 ConvertTo-Json | Set-Content -LiteralPath $receipt -Encoding UTF8
}
