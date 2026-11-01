# Local synthetic evidence only. Does not invoke the launcher, psql, SQL or network.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Stage4-Results.ps1')
$testDirectory=Join-Path ([IO.Path]::GetTempPath()) ('vader-stage4-offline-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($testDirectory)
$files=@()
$count=0
function Exercise([string]$Name,[string[]]$Lines,[int]$Code,[string]$ExpectedFailure) {
 $path=Join-Path $testDirectory ($Name+'.txt')
 [IO.File]::WriteAllLines($path,$Lines,[Text.UTF8Encoding]::new($false))
 $script:files+=,$path
 $message=$null
 try { $null=Read-Stage4Result -Path $path -ExitCode $Code -Phase runtime } catch { $message=$_.Exception.Message }
 if ($ExpectedFailure) {
  if (!$message -or $message -notlike "*$ExpectedFailure*") { throw "Wrong failure for $Name : $message" }
 } elseif ($message) { throw "Unexpected failure for $Name : $message" }
 $script:count++
}
try {
 Exercise 'native_failure_empty_output' @() 3 'psql failed (exit 3)'
 Exercise 'metadata_failure' @('{"record_type":"metadata_check","phase":"preflight","matches_expected":false}',
  '{"record_type":"failure","code":"STAGE4_METADATA_MISMATCH"}') 3 'STAGE4_METADATA_MISMATCH'
 Exercise 'failure_with_zero_exit' @('{"record_type":"failure","code":"TEST_ROUTE_REJECTED"}') 0 'Failure diagnostic despite zero client exit'
 Exercise 'zero_exit_empty' @() 0 'No unique stage4_runtime success result'
 $success=@('{"record_type":"metadata_check","phase":"preflight","matches_expected":true}',
  '{"record_type":"metadata_check","phase":"restored","matches_expected":true}',
  '{"test":"stage4_runtime","passed":true,"fixture_removed":true}', 'STAGE4_ROLLBACK_ACKNOWLEDGED')
 Exercise 'success_with_diagnostics' $success 0 ''
 Exercise 'missing_rollback_ack' $success[0..2] 0 'Rollback acknowledgement missing'
 Exercise 'duplicate_result' ($success+@('{"test":"stage4_runtime","passed":true,"fixture_removed":true}')) 0 'No unique stage4_runtime success result'
 Exercise 'malformed_json' @('{broken') 0 'output JSON is malformed'
 Exercise 'wrong_phase' @('{"test":"stage4_cleanup","passed":true,"fixture_removed":true}') 0 'No unique stage4_runtime success result'
 Write-Host "PASS: $count offline failure/success evidence paths. No launcher/SQL/database invocation."
} finally {
 # Delete only individually named synthetic files; never touch historical evidence.
 foreach ($file in $files) { [IO.File]::Delete($file) }
 [IO.Directory]::Delete($testDirectory)
}
