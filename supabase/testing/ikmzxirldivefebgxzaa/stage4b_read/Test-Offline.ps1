# Synthetic local parser tests only; never invokes psql or the runtime launcher.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Read-Results.ps1')
$dir=Join-Path ([IO.Path]::GetTempPath()) ('vader-read-parser-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($dir);$files=@();$count=0
function Exercise([string]$Name,[string[]]$Lines,[int]$Code,[string]$Expected) {
 $path=Join-Path $dir ($Name+'.txt');[IO.File]::WriteAllLines($path,$Lines,[Text.UTF8Encoding]::new($false));$script:files+=,$path
 $failure=$null
 try {$null=Read-Stage4BReadResult -Path $path -ExitCode $Code -Phase runtime} catch {$failure=$_.Exception.Message}
 if ($Expected) {if (!$failure -or $failure -notlike "*$Expected*") {throw "Wrong failure: $Name : $failure"}} elseif ($failure) {throw $failure}
 $script:count++
}
try {
 $lines=@()
 foreach($phase in @('preflight','granted','tested','restored')) {
  $lines+=(@{record_type='metadata_check';phase=$phase;matches_expected=($phase -in @('preflight','restored'));expected_md5='90a71db3b16ed177b3455f61a59343b2'} | ConvertTo-Json -Compress)
 }
 $delta='{"record_type":"permission_delta","passed":true,"effective_select_additions":5,"direct_acl_additions":5,"grantable":false}'
 $lines+=@($delta,$delta,'{"record_type":"collision_check","passed":true}','{"record_type":"collision_check","passed":true}',
 '{"record_type":"restricted_role_reads","passed":true,"assertions":15}')
 $cases=@(0..13 | ForEach-Object {@{case="synthetic_$_";passed=$true;assertions=$(if($_ -eq 13){5}else{45})}})
 $lines+=(@{record_type='read_suite';passed=$true;cases=14;assertions=590;mode='SQL_ROLE_SIMULATION';case_results=$cases} | ConvertTo-Json -Compress -Depth 8)
 $lines+=@('{"test":"stage4b_read_runtime","passed":true,"fixture_removed":true,"grant_rolled_back":true}','STAGE4B_READ_ROLLBACK_ACKNOWLEDGED')
 Exercise 'valid_diagnostics_and_suite' $lines 0 ''
 Exercise 'nonzero_empty' @() 3 'psql failed (exit 3)'
 Exercise 'no_result' @() 0 'Missing/duplicate success'
 Exercise 'missing_ack' $lines[0..($lines.Count-2)] 0 'Rollback acknowledgement absent'
 Exercise 'missing_delta' @($lines | Where-Object {$_ -notlike '*permission_delta*'}) 0 'Exact permission delta not proven'
 Exercise 'extra_privilege' @($lines | ForEach-Object {$_.Replace('"effective_select_additions":5','"effective_select_additions":6')}) 0 'Exact permission delta not proven'
 Exercise 'failure_despite_zero_exit' ($lines+@('{"record_type":"failure","code":"denied"}')) 0 'Failure record despite zero exit'
 Exercise 'missing_restricted_role_reads' @($lines | Where-Object {$_ -notlike '*restricted_role_reads*'}) 0 'Anonymous/service-role restrictions not proven'
 Write-Host "PASS: $count offline parser/failure cases; no database/network/launcher execution."
} finally {
 foreach($file in $files){[IO.File]::Delete($file)}
 [IO.Directory]::Delete($dir)
}
