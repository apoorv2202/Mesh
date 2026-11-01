[CmdletBinding()]
param(
 [ValidateSet('Validate','Runtime','CleanupCheck')][string]$Action='Validate',
 [switch]$ApproveTestRollback,
 [string]$ReviewedPinsSha256
)
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$pinPath=Join-Path $root 'pins.json'
$pins=Get-Content -LiteralPath $pinPath -Raw | ConvertFrom-Json
if ($pins.test_ref -cne 'ikmzxirldivefebgxzaa') { throw 'TEST pins required' }
foreach ($pin in $pins.files.PSObject.Properties) {
 if ((Get-FileHash -LiteralPath (Join-Path $root $pin.Name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pin.Value) { throw "Pin mismatch: $($pin.Name)" }
}
if ($Action -eq 'Validate') { Write-Host 'PASS: local pins only. No database connection.'; return }
if (!$ApproveTestRollback -or $ReviewedPinsSha256 -cne (Get-FileHash -LiteralPath $pinPath -Algorithm SHA256).Hash.ToLowerInvariant()) { throw 'Separate authorization and independently reviewed pins hash required' }
$ready=Get-Content -LiteralPath (Join-Path $root 'execution_readiness.json') -Raw | ConvertFrom-Json
if (!$ready.authorizable -and $Action -eq 'Runtime') { throw 'NO-GO: unresolved review blockers. No connection attempted.' }
if ($Host.Name -ne 'ConsoleHost') { throw 'Use an interactive PowerShell terminal for the TEST password prompt' }
$originalAclMd5='unused-in-runtime'
if ($Action -eq 'CleanupCheck') {
 $evidenceRoot=Join-Path $root 'evidence'
 $prior=Get-Content -LiteralPath (Join-Path $evidenceRoot 'runtime.receipt.json') -Raw | ConvertFrom-Json
 $priorLog=Join-Path $evidenceRoot 'runtime.txt'
 if ($prior.test_ref -cne $pins.test_ref -or
  (Get-FileHash -LiteralPath $priorLog -Algorithm SHA256).Hash.ToLowerInvariant() -cne $prior.output_sha256) { throw 'Prior attempt evidence invalid; no cleanup connection attempted' }
 $baseline=@(foreach($line in Get-Content -LiteralPath $priorLog){if($line.Trim().StartsWith('{')){$o=$line|ConvertFrom-Json;if($o.record_type -ceq 'acl_baseline'){$o}}})
 if($baseline.Count -ne 1 -or $baseline[0].md5 -cnotmatch '^[0-9a-f]{32}$'){throw 'Original ACL fingerprint missing/ambiguous; separate investigation required'}
 $originalAclMd5=$baseline[0].md5
}
$psql='C:\Program Files\PostgreSQL\18\bin\psql.exe'
$ca='C:\Users\APOORV\Downloads\prod-ca-2021.crt'
if (!(Test-Path -LiteralPath $psql -PathType Leaf) -or
 (Get-FileHash -LiteralPath $ca -Algorithm SHA256).Hash.ToLowerInvariant() -cne '700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7') { throw 'Reviewed psql/CA required' }
$cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2($ca)
$basic=$cert.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.19'}
if (!$basic -or !$basic.CertificateAuthority -or $cert.HasPrivateKey -or
 $cert.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or $cert.NotAfter.ToUniversalTime() -lt [DateTime]::UtcNow) { throw 'Invalid CA certificate' }
$folder=Join-Path $root 'evidence'
$null=New-Item -ItemType Directory -Path $folder -Force
$phase=if($Action -eq 'Runtime'){'runtime'}else{'cleanup_check'}
$output=Join-Path $folder "$phase.txt";$errors=Join-Path $folder "$phase.stderr.txt";$receipt=Join-Path $folder "$phase.receipt.json"
foreach($path in @($output,$errors,$receipt)){if(Test-Path -LiteralPath $path){throw 'Prior attempt/evidence exists; no overwrite or automatic retry'}}
# Reserve this one attempt before any database process starts.
$stream=[IO.File]::Open($receipt,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$stream.Dispose()
$saved=@{};$passed=$false;$failure=$null;$exitCode=$null
try {
 # Clear every PG* routing/SSL/service/credential override, then restore on exit.
 foreach($item in Get-ChildItem Env: | Where-Object {$_.Name -like 'PG*'}) {
  $saved[$item.Name]=$item.Value;[Environment]::SetEnvironmentVariable($item.Name,$null,'Process')
 }
 $env:PGHOST='aws-0-eu-west-1.pooler.supabase.com';$env:PGPORT='5432';$env:PGDATABASE='postgres'
 $env:PGUSER='postgres.ikmzxirldivefebgxzaa';$env:PGSSLMODE='verify-full';$env:PGSSLROOTCERT=$ca
 $env:PGCONNECT_TIMEOUT='10';$env:PGAPPNAME="mesh-stage4b-write-$phase"
 $env:PGCLIENTENCODING='UTF8'
 $ro=if($Action -eq 'Runtime'){'off'}else{'on'}
 $env:PGOPTIONS="-c default_transaction_read_only=$ro -c statement_timeout=90000 -c lock_timeout=5000 -c idle_in_transaction_session_timeout=90000"
 $argsList=@('-X','-W','-q','-A','-t','--host',$env:PGHOST,'--port','5432','--username',$env:PGUSER,'--dbname','postgres',
 '--set','ON_ERROR_STOP=1','--set','VERBOSITY=verbose','--set','vader_test_ref=ikmzxirldivefebgxzaa',
 '--set','stage4bwrite_approved=ikmzxirldivefebgxzaa','--set','user_a=72a7251d-b69b-4149-8a7f-a082e4b920e9',
 '--set','user_b=8c9907c9-4acf-480b-aaee-dcd08f3cbc6a','--set','expected_post_md5=90a71db3b16ed177b3455f61a59343b2',
 '--set',"expected_write_acl_md5=$originalAclMd5",
 '--file',(Join-Path $root "$phase.sql"),'--output',$output)
 & $psql @argsList 2> $errors
 $exitCode=$LASTEXITCODE
 if ($exitCode -ne 0) { throw "psql failed with exit $exitCode. Original error evidence: $errors" }
 $lines=Get-Content -LiteralPath $output
 $records=@(foreach($line in $lines){if($line.Trim().StartsWith('{')){try{$line | ConvertFrom-Json}catch{throw 'Malformed evidence JSON'}}})
 $kind=if($Action -eq 'Runtime'){'stage4b_write_result'}else{'stage4b_write_cleanup'}
 $results=@($records | Where-Object {$_.record_type -ceq $kind})
 if($results.Count -ne 1 -or !$results[0].passed -or !$results[0].metadata_restored -or !$results[0].fixtures_absent){throw 'Successful result evidence missing/ambiguous'}
 if($Action -eq 'Runtime') {
  if(@($lines | Where-Object {$_ -ceq 'STAGE4B_WRITE_ROLLBACK_ACKNOWLEDGED'}).Count -ne 1){throw 'Rollback acknowledgement missing/ambiguous'}
  $asserts=@($records | Where-Object {$_.record_type -ceq 'write_assertions'})
  if($asserts.Count -ne 1 -or $asserts[0].human -ne 46 -or $asserts[0].membership_denials -ne 20 -or $asserts[0].fk_denials -ne 2 -or !$asserts[0].audit_fault){throw 'Expected assertions incomplete'}
 }
 $passed=$true
 Write-Host "PASS for $phase limited SQL-role scope. Machine LOGIN, concurrency and real JWT remain unverified. STOP."
} catch {$failure=$_.Exception.Message;throw} finally {
 foreach($item in @(Get-ChildItem Env: | Where-Object {$_.Name -like 'PG*'})){[Environment]::SetEnvironmentVariable($item.Name,$null,'Process')}
 foreach($name in $saved.Keys){[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')}
 $hash=if(Test-Path -LiteralPath $output){(Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant()}else{$null}
 $errorHash=if(Test-Path -LiteralPath $errors){(Get-FileHash -LiteralPath $errors -Algorithm SHA256).Hash.ToLowerInvariant()}else{$null}
 @{test_ref=$pins.test_ref;phase=$phase;passed=$passed;exit_code=$exitCode;output_sha256=$hash;stderr_sha256=$errorHash;
  pins_sha256=$ReviewedPinsSha256;failure=$failure;recorded_at_utc=[DateTime]::UtcNow.ToString('o');
  machine_login_verified=$false;real_jwt_verified=$false;concurrent_database_sessions_verified=$false} |
  ConvertTo-Json | Set-Content -LiteralPath $receipt -Encoding UTF8
}
