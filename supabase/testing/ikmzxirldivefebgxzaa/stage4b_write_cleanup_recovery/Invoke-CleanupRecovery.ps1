[CmdletBinding()]
param([switch]$ApproveCleanupRecovery,[string]$ReviewedManifestSha256)
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$manifestPath=Join-Path $root 'pins.json'
if(!$ApproveCleanupRecovery -or $ReviewedManifestSha256 -cnotmatch '^[0-9a-f]{64}$' -or
 $ReviewedManifestSha256 -cne (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()) {
 throw 'Separate cleanup-recovery approval and exact newly reviewed manifest hash required'
}
$manifest=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
foreach($required in @('Invoke-CleanupRecovery.ps1','Recovery-Support.ps1','ConsoleProbe.cs','readiness.json')) {
 if(!$manifest.files -or !$manifest.files.PSObject.Properties[$required]){throw 'Required recovery code missing from reviewed manifest'}
}
foreach($pin in $manifest.files.PSObject.Properties){
 if((Get-FileHash -LiteralPath (Join-Path $root $pin.Name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pin.Value){throw "Pinned recovery input changed: $($pin.Name)"}
}
# Verify helpers before loading their code.
. (Join-Path $root 'Recovery-Support.ps1')
$readiness=Get-Content -LiteralPath (Join-Path $root 'readiness.json') -Raw|ConvertFrom-Json
Assert-RecoveryState -Manifest $manifest -Readiness $readiness
$original=Join-Path $root '../stage4b_write_phase2'
$prior=Get-Content -LiteralPath (Join-Path $original 'evidence/runtime.receipt.json') -Raw|ConvertFrom-Json
if($prior.test_ref -cne 'ikmzxirldivefebgxzaa' -or $prior.pins_sha256 -cne '9ce235e2887aea69bc0772c09ff8e646412cb845ce97cfd8df96e6d52976df68' -or $prior.passed -ne $false){throw 'Original failed TEST Runtime receipt required'}
$priorText=Get-Content -LiteralPath (Join-Path $original 'evidence/runtime.txt') -Raw
if((Get-FileHash -LiteralPath (Join-Path $original 'evidence/runtime.txt') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $prior.output_sha256){throw 'Original Runtime log hash mismatch'}
$baseline=@(foreach($line in $priorText -split "`n"){if($line.Trim().StartsWith('{')){$o=$line|ConvertFrom-Json;if($o.record_type -ceq 'acl_baseline'){$o}}})
if($baseline.Count -ne 1 -or $baseline[0].md5 -cne 'e4e671b562707df52adc76c3c26e14af'){throw 'Original ACL baseline missing/changed'}
$client='C:\Program Files\PostgreSQL\18\bin\psql.exe'
$ca='C:\Users\APOORV\Downloads\prod-ca-2021.crt'
if(!(Test-Path -LiteralPath $client -PathType Leaf) -or [Diagnostics.FileVersionInfo]::GetVersionInfo($client).ProductVersion -cne '18.6'){throw 'Reviewed Windows psql 18.6 required'}
if((Get-FileHash -LiteralPath $ca -Algorithm SHA256).Hash.ToLowerInvariant() -cne '700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7'){throw 'CA pin mismatch'}
$cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2($ca)
$basic=$cert.Extensions|Where-Object{$_.Oid.Value -eq '2.5.29.19'}
if(!$basic -or !$basic.CertificateAuthority -or $cert.HasPrivateKey -or $cert.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or $cert.NotAfter.ToUniversalTime() -lt [DateTime]::UtcNow){throw 'Invalid CA'}
Assert-InteractiveRecoveryConsole -ConsoleSource (Join-Path $root 'ConsoleProbe.cs')
$attempt=Join-Path $root 'evidence/attempt_01'
Assert-NewRecoveryDirectory -Path $attempt
$null=[IO.Directory]::CreateDirectory($attempt)
# CreateNew is the atomic one-attempt reservation, even if another process races
# the directory check. No historical file is opened for write.
$receiptPath=Join-Path $attempt 'receipt.json'
$receipt=[IO.File]::Open($receiptPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
$paths=@{result=(Join-Path $attempt 'result.txt');stdout=(Join-Path $attempt 'native_stdout.txt');stderr=(Join-Path $attempt 'stderr.txt')}
$passed=$false;$failure=$null;$exitCode=$null;$started=$false
try {
 foreach($path in $paths.Values){$s=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$s.Dispose()}
 $info=New-Object Diagnostics.ProcessStartInfo
 $info.FileName=$client;$info.UseShellExecute=$false;$info.CreateNoWindow=$false
 $info.RedirectStandardInput=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 foreach($name in @($info.EnvironmentVariables.Keys)){if($name -like 'PG*' -or $name -eq 'OSTYPE'){$info.EnvironmentVariables.Remove($name)}}
 # Child-only environment: no password variable, no password files configured.
 $info.EnvironmentVariables['PGHOST']='aws-0-eu-west-1.pooler.supabase.com'
 $info.EnvironmentVariables['PGPORT']='5432';$info.EnvironmentVariables['PGDATABASE']='postgres'
 $info.EnvironmentVariables['PGUSER']='postgres.ikmzxirldivefebgxzaa'
 $info.EnvironmentVariables['PGSSLMODE']='verify-full';$info.EnvironmentVariables['PGSSLROOTCERT']=$ca
 $info.EnvironmentVariables['PGCONNECT_TIMEOUT']='10';$info.EnvironmentVariables['PGCLIENTENCODING']='UTF8'
 # Disable libpq's default password-file fallback without creating a file.
 # result.txt is a reserved regular file, so this child path cannot be a passfile.
 $info.EnvironmentVariables['PGPASSFILE']=Join-Path $paths.result 'password_files_disabled'
 $info.EnvironmentVariables['PGAPPNAME']='mesh-cleanup-recovery-attempt01'
 $info.EnvironmentVariables['PGOPTIONS']='-c default_transaction_read_only=on -c statement_timeout=90000 -c lock_timeout=5000 -c idle_in_transaction_session_timeout=90000'
 $sql=[IO.Path]::GetFullPath((Join-Path $original 'cleanup_check.sql'))
 # Every argument is fixed/reviewed; no user connection string or SQL file input.
 # Windows paths are quoted; these fixed paths cannot contain embedded quotes.
 $info.Arguments='-X -W -q -A -t --host aws-0-eu-west-1.pooler.supabase.com --port 5432 --username postgres.ikmzxirldivefebgxzaa --dbname postgres --set ON_ERROR_STOP=1 --set VERBOSITY=verbose --set vader_test_ref=ikmzxirldivefebgxzaa --set stage4bwrite_approved=ikmzxirldivefebgxzaa --set user_a=72a7251d-b69b-4149-8a7f-a082e4b920e9 --set user_b=8c9907c9-4acf-480b-aaee-dcd08f3cbc6a --set expected_post_md5=90a71db3b16ed177b3455f61a59343b2 --set expected_write_acl_md5=e4e671b562707df52adc76c3c26e14af --file "'+$sql+'" --output "'+$paths.result+'"'
 $started=$true
 $native=Invoke-RecoveryCapturedProcess -Info $info
 $exitCode=$native.ExitCode
 [IO.File]::WriteAllText($paths.stdout,$native.Stdout,[Text.Encoding]::UTF8)
 [IO.File]::WriteAllText($paths.stderr,$native.Stderr,[Text.Encoding]::UTF8)
 Assert-CleanupRecoveryResult -ExitCode $exitCode -ResultText ([IO.File]::ReadAllText($paths.result))
 $passed=$true
 Write-Host 'PASS: fresh read-only TEST restoration verification. Original Runtime and CleanupCheck remain FAIL. STOP.'
} catch {$failure=$_.Exception.Message;throw} finally {
 $hashes=@{}
 foreach($name in $paths.Keys){$hashes[$name]=if(Test-Path -LiteralPath $paths[$name]){(Get-FileHash -LiteralPath $paths[$name] -Algorithm SHA256).Hash.ToLowerInvariant()}else{$null}}
 $record=@{test_ref='ikmzxirldivefebgxzaa';scope='read_only_cleanup_recovery';attempt='attempt_01';passed=$passed;
  process_start_requested=$started;exit_code=$exitCode;failure=$failure;pins_sha256=$ReviewedManifestSha256;hashes=$hashes;
  original_runtime_output_sha256=$prior.output_sha256;original_manifest_sha256=$prior.pins_sha256;
  expected_metadata_md5='90a71db3b16ed177b3455f61a59343b2';expected_acl_md5=$baseline[0].md5;recorded_at_utc=[DateTime]::UtcNow.ToString('o')}
 $bytes=[Text.Encoding]::UTF8.GetBytes(($record|ConvertTo-Json -Depth 5))
 try{$receipt.Write($bytes,0,$bytes.Length);$receipt.Flush()}finally{$receipt.Dispose()}
}
