[CmdletBinding()]
param(
 [ValidateSet('Validate','Runtime','CleanupCheck')][string]$Action='Validate',
 [switch]$ApproveStage4,
 [string]$UserA,
 [string]$UserB
)
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$pins=Get-Content -LiteralPath (Join-Path $root 'pins.json') -Raw | ConvertFrom-Json
if ($pins.test_ref -cne 'ikmzxirldivefebgxzaa') { throw 'TEST mismatch' }
if ($pins.harness_revision -ne 2) { throw 'Reviewed revision-2 pins required' }
foreach ($pin in $pins.files.PSObject.Properties) {
 if ((Get-FileHash -LiteralPath (Join-Path $root $pin.Name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pin.Value) { throw "Reviewed artifact changed: $($pin.Name)" }
}
. (Join-Path $root 'Stage4-Results.ps1')
$postPath=Join-Path $root '../stage3/evidence/verify_no_dml.txt'
$postReceipt=Get-Content -LiteralPath (Join-Path $root '../stage3/evidence/verify_no_dml.receipt.json') -Raw | ConvertFrom-Json
if (!$postReceipt.passed -or $postReceipt.test_ref -cne $pins.test_ref -or (Get-FileHash -LiteralPath $postPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $postReceipt.output_sha256) { throw 'Post-Migration01 evidence invalid' }
if ($Action -eq 'Validate') { Write-Host 'PASS: Stage4 local integrity. NO SQL, users or network actions executed.'; return }
if (!$ApproveStage4) { throw 'Explicit Stage4 execution authorization and -ApproveStage4 required' }
$a=[guid]::Parse($UserA); $b=[guid]::Parse($UserB)
if ($a -eq $b -or $a -eq [guid]::Empty -or $b -eq [guid]::Empty) { throw 'Two distinct new synthetic TEST Auth UUIDs required' }
$folder=Join-Path $root 'evidence_r2'
$null=New-Item -ItemType Directory -Path $folder -Force
$phase=if ($Action -eq 'Runtime') {'runtime'} else {'cleanup_check'}
$output=Join-Path $folder "$phase.txt"
$receipt=Join-Path $folder "$phase.receipt.json"
if ((Test-Path -LiteralPath $output) -or (Test-Path -LiteralPath $receipt)) { throw 'Phase reserved/executed. No retry or overwrite.' }
if ($Action -eq 'CleanupCheck') {
 $r=Get-Content -LiteralPath (Join-Path $folder 'runtime.receipt.json') -Raw | ConvertFrom-Json
 if (!$r.passed -or $r.harness_revision -ne 2 -or $r.test_ref -cne $pins.test_ref -or $r.user_a -cne $a.ToString() -or $r.user_b -cne $b.ToString() -or
 (Get-FileHash -LiteralPath (Join-Path $folder 'runtime.txt') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $r.output_sha256) { throw 'Runtime prerequisite invalid' }
}
$line=(Get-Content -LiteralPath $postPath -Raw).Trim()
$md5=[System.Security.Cryptography.MD5]::Create()
try { $digest=([BitConverter]::ToString($md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($line)))).Replace('-','').ToLowerInvariant() } finally { $md5.Dispose() }
$psql='C:\Program Files\PostgreSQL\18\bin\psql.exe'
$ca='C:\Users\APOORV\Downloads\prod-ca-2021.crt'
if (!(Test-Path -LiteralPath $psql -PathType Leaf)) { throw 'psql missing' }
if ((Get-FileHash -LiteralPath $ca -Algorithm SHA256).Hash.ToLowerInvariant() -cne '700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7') { throw 'Reviewed CA changed' }
$cert=New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ca)
$basic=$cert.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.19'}
if (!$basic -or !$basic.CertificateAuthority -or $cert.HasPrivateKey -or $cert.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or $cert.NotAfter.ToUniversalTime() -lt [DateTime]::UtcNow) { throw 'Invalid CA' }
$names=@('PGHOST','PGHOSTADDR','PGUSER','PGPORT','PGDATABASE','PGSERVICE','PGSERVICEFILE','PGPASSWORD','PGPASSFILE','PGOPTIONS','PGSSLMODE','PGSSLROOTCERT','PGAPPNAME','PGCONNECT_TIMEOUT','PGSSLCERT','PGSSLKEY','PGSSLCRL','PGSSLCRLDIR','PGREQUIRESSL')
$saved=@{}
$stream=[IO.File]::Open($receipt,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
$stream.Dispose()
$passed=$false
$failureMessage=$null
$result=$null
try {
 foreach ($name in $names) { $saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process'); [Environment]::SetEnvironmentVariable($name,$null,'Process') }
 $env:PGHOST='aws-0-eu-west-1.pooler.supabase.com'; $env:PGUSER='postgres.ikmzxirldivefebgxzaa'
 $env:PGPORT='5432'; $env:PGDATABASE='postgres'; $env:PGSSLMODE='verify-full'; $env:PGSSLROOTCERT=$ca
 $env:PGCONNECT_TIMEOUT='10'; $env:PGAPPNAME="mesh-stage4-$phase"
 $ro=if ($Action -eq 'Runtime') {'off'} else {'on'}
 $env:PGOPTIONS="-c default_transaction_read_only=$ro -c statement_timeout=60000 -c lock_timeout=5000 -c idle_in_transaction_session_timeout=60000"
 $psqlArgs=@('-X','-W','-q','-A','-t','--host',$env:PGHOST,'--port','5432','--username',$env:PGUSER,'--dbname','postgres',
 '--set','ON_ERROR_STOP=1','--set','VERBOSITY=verbose','--set','vader_test_ref=ikmzxirldivefebgxzaa','--set','stage4_approved=ikmzxirldivefebgxzaa',
 '--set',"user_a=$a",'--set',"user_b=$b",'--set',"expected_post_md5=$digest",'--file',(Join-Path $root "$phase.sql"),'--output',$output)
 & $psql @psqlArgs
 $exitCode=$LASTEXITCODE
 $result=Read-Stage4Result -Path $output -ExitCode $exitCode -Phase $phase
 $passed=$true
 Write-Host 'PASS for limited ACL/helper/FK/control cases. RLS row filtering remains BLOCKED. STOP.'
} catch {
 $failureMessage=$_.Exception.Message
 throw
} finally {
 foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name,$saved[$name],'Process') }
 $hash=if (Test-Path -LiteralPath $output) {(Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant()} else {$null}
 @{test_ref=$pins.test_ref;harness_revision=2;phase=$phase;passed=$passed;user_a=$a.ToString();user_b=$b.ToString();
 output_sha256=$hash;recorded_at_utc=[DateTime]::UtcNow.ToString('o');rls_row_filtering_tested=$false;
 failure_message=$failureMessage;metadata_preservation_verified=($passed -and $null -ne $result);
 grants_or_policies_changed=$(if ($passed) {$false} else {$null});migration02_executed=$false} | ConvertTo-Json | Set-Content -LiteralPath $receipt -Encoding UTF8
}
