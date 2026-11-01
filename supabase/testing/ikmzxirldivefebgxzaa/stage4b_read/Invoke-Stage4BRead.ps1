[CmdletBinding()]
param(
 [ValidateSet('Validate','Runtime','CleanupCheck')][string]$Action='Validate',
 [switch]$ApproveStage4BRead,
 [string]$UserA,
 [string]$UserB
)
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$pins=Get-Content -LiteralPath (Join-Path $root 'pins.json') -Raw | ConvertFrom-Json
if ($pins.test_ref -cne 'ikmzxirldivefebgxzaa' -or $pins.harness -cne 'stage4b_read_v1') { throw 'Reviewed TEST pins required' }
foreach ($pin in $pins.files.PSObject.Properties) {
 if ((Get-FileHash -LiteralPath (Join-Path $root $pin.Name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pin.Value) { throw "Reviewed artifact changed: $($pin.Name)" }
}
foreach ($phase in @('runtime','cleanup_check')) {
 $dir=Join-Path $root '../stage4/evidence_r2'
 $r=Get-Content -LiteralPath (Join-Path $dir "$phase.receipt.json") -Raw | ConvertFrom-Json
 if (!$r.passed -or $r.test_ref -cne $pins.test_ref -or $r.harness_revision -ne 2 -or
 (Get-FileHash -LiteralPath (Join-Path $dir "$phase.txt") -Algorithm SHA256).Hash.ToLowerInvariant() -cne $r.output_sha256) { throw 'R2 prerequisite evidence invalid' }
}
. (Join-Path $root 'Read-Results.ps1')
if ($Action -eq 'Validate') { Write-Host 'PASS: local Stage4B-read integrity. NO SQL/network/execution.'; return }
if (!$ApproveStage4BRead) { throw 'Separate TEST execution authorization and -ApproveStage4BRead required' }
$a=[guid]::Parse($UserA);$b=[guid]::Parse($UserB)
if ($a.ToString() -cne '72a7251d-b69b-4149-8a7f-a082e4b920e9' -or $b.ToString() -cne '8c9907c9-4acf-480b-aaee-dcd08f3cbc6a') { throw 'Use only the two reviewed synthetic TEST identities in their mapped roles' }
$folder=Join-Path $root 'evidence'
$null=New-Item -ItemType Directory -Path $folder -Force
$phase=if ($Action -eq 'Runtime') {'runtime'} else {'cleanup_check'}
$output=Join-Path $folder "$phase.txt";$receipt=Join-Path $folder "$phase.receipt.json"
if ((Test-Path -LiteralPath $receipt) -or (Test-Path -LiteralPath $output)) { throw 'Attempt reserved/executed; no overwrite or automatic retry' }
if ($Action -eq 'CleanupCheck') {
 $r=Get-Content -LiteralPath (Join-Path $folder 'runtime.receipt.json') -Raw | ConvertFrom-Json
 if (!$r.passed -or $r.harness -cne $pins.harness -or $r.test_ref -cne $pins.test_ref -or $r.user_a -cne $a.ToString() -or $r.user_b -cne $b.ToString() -or
 (Get-FileHash -LiteralPath (Join-Path $folder 'runtime.txt') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $r.output_sha256) { throw 'Successful Stage4B-read runtime evidence required' }
}
$post=(Get-Content -LiteralPath (Join-Path $root '../stage3/evidence/verify_no_dml.txt') -Raw).Trim()
$md5=[Security.Cryptography.MD5]::Create()
try {$digest=([BitConverter]::ToString($md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($post)))).Replace('-','').ToLowerInvariant()} finally {$md5.Dispose()}
if ($digest -cne $pins.baseline_md5) { throw 'Trusted baseline changed' }
$psql='C:\Program Files\PostgreSQL\18\bin\psql.exe';$ca='C:\Users\APOORV\Downloads\prod-ca-2021.crt'
if (!(Test-Path -LiteralPath $psql -PathType Leaf) -or (Get-FileHash -LiteralPath $ca -Algorithm SHA256).Hash.ToLowerInvariant() -cne '700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7') { throw 'Reviewed client/CA unavailable' }
$cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2($ca)
$basic=$cert.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.19'}
if (!$basic -or !$basic.CertificateAuthority -or $cert.HasPrivateKey -or $cert.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or $cert.NotAfter.ToUniversalTime() -lt [DateTime]::UtcNow) { throw 'Invalid CA' }
$names=@('PGHOST','PGHOSTADDR','PGUSER','PGPORT','PGDATABASE','PGSERVICE','PGSERVICEFILE','PGPASSWORD','PGPASSFILE','PGOPTIONS','PGSSLMODE','PGSSLROOTCERT','PGAPPNAME','PGCONNECT_TIMEOUT','PGSSLCERT','PGSSLKEY','PGSSLCRL','PGSSLCRLDIR','PGREQUIRESSL')
$saved=@{};$passed=$false;$failure=$null
$stream=[IO.File]::Open($receipt,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$stream.Dispose()
try {
 foreach($name in $names){$saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process');[Environment]::SetEnvironmentVariable($name,$null,'Process')}
 $env:PGHOST='aws-0-eu-west-1.pooler.supabase.com';$env:PGUSER='postgres.ikmzxirldivefebgxzaa';$env:PGPORT='5432';$env:PGDATABASE='postgres'
 $env:PGSSLMODE='verify-full';$env:PGSSLROOTCERT=$ca;$env:PGCONNECT_TIMEOUT='10';$env:PGAPPNAME="mesh-stage4b-read-$phase"
 $ro=if($Action -eq 'Runtime'){'off'}else{'on'}
 $env:PGOPTIONS="-c default_transaction_read_only=$ro -c statement_timeout=60000 -c lock_timeout=5000 -c idle_in_transaction_session_timeout=60000"
 $argsList=@('-X','-W','-q','-A','-t','--host',$env:PGHOST,'--port','5432','--username',$env:PGUSER,'--dbname','postgres','--set','ON_ERROR_STOP=1','--set','VERBOSITY=verbose',
 '--set','vader_test_ref=ikmzxirldivefebgxzaa','--set','stage4bread_approved=ikmzxirldivefebgxzaa','--set',"user_a=$a",'--set',"user_b=$b",'--set',"expected_post_md5=$digest",'--file',(Join-Path $root "$phase.sql"),'--output',$output)
 & $psql @argsList
 $code=$LASTEXITCODE
 $null=Read-Stage4BReadResult -Path $output -ExitCode $code -Phase $phase
 $passed=$true
 Write-Host 'PASS: SQL-role tenant-filtered reads; temporary SELECT grant and fixtures rolled back. Real JWT/API reads NOT tested. STOP.'
} catch {$failure=$_.Exception.Message;throw} finally {
 foreach($name in $saved.Keys){[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')}
 $hash=if(Test-Path -LiteralPath $output){(Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant()}else{$null}
 @{test_ref=$pins.test_ref;harness=$pins.harness;phase=$phase;passed=$passed;user_a=$a.ToString();user_b=$b.ToString();output_sha256=$hash;
 failure_message=$failure;recorded_at_utc=[DateTime]::UtcNow.ToString('o');authentication_mode='SQL_ROLE_SIMULATION';real_jwt_tested=$false;
 permissions_restored_verified=$passed;migration02_executed=$false} | ConvertTo-Json | Set-Content -LiteralPath $receipt -Encoding UTF8
}
