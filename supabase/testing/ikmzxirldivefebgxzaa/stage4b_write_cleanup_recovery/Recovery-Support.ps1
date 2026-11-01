# Shared local helpers. Importing defines functions only; no process/connection starts.
function Assert-RecoveryApproval {
 param([bool]$Approved,[string]$ReviewedHash,[string]$ManifestPath)
 if(!$Approved -or $ReviewedHash -cnotmatch '^[0-9a-f]{64}$' -or
  $ReviewedHash -cne (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()) {
  throw 'Separate cleanup-recovery approval and exact newly reviewed manifest hash required'
 }
}
function Assert-RecoveryState {
 param($Manifest,$Readiness)
 if($Manifest.test_ref -cne 'ikmzxirldivefebgxzaa' -or $Readiness.test_ref -cne 'ikmzxirldivefebgxzaa' -or
  $Manifest.scope -cne 'read_only_cleanup_recovery' -or $Readiness.scope -cne 'read_only_cleanup_recovery' -or
  $Manifest.execution_authorized -isnot [bool] -or $Manifest.execution_authorized -or
  $Readiness.database_execution_authorized -isnot [bool] -or $Readiness.database_execution_authorized) {
  throw 'Only TEST read-only cleanup preparation without persistent authorization is supported'
 }
 if(@($Readiness.PSObject.Properties.Name | Where-Object {$_ -notin @('test_ref','scope','database_execution_authorized')}).Count -ne 0) {
  throw 'Unexpected recovery readiness field'
 }
 if(@($Manifest.PSObject.Properties.Name | Where-Object {$_ -notin @('test_ref','scope','revision','execution_authorized','files')}).Count -ne 0 -or $Manifest.revision -cne 'cleanup_recovery_v1') {
  throw 'Unexpected recovery manifest structure/revision'
 }
}
function Assert-NewRecoveryDirectory {
 param([string]$Path)
 if(Test-Path -LiteralPath $Path){throw 'Recovery evidence already exists; no overwrite or retry'}
}
function Assert-InteractiveRecoveryConsole {
 param([string]$ConsoleSource)
 if($Host.Name -ne 'ConsoleHost' -or [Console]::IsInputRedirected -or [Console]::IsOutputRedirected) {
  throw 'A real interactive ConsoleHost with unredirected input/output is required; no attempt started'
 }
 if(!('VaderRecovery.ConsoleProbe' -as [type])){Add-Type -TypeDefinition ([IO.File]::ReadAllText($ConsoleSource))}
 if(![VaderRecovery.ConsoleProbe]::Available()){throw 'Native console handles unavailable; no attempt started'}
}
function Invoke-RecoveryCapturedProcess {
 param([Diagnostics.ProcessStartInfo]$Info)
 if($Info.UseShellExecute -or !$Info.RedirectStandardError -or !$Info.RedirectStandardOutput){throw 'Explicit captured native-process configuration required'}
 $process=New-Object Diagnostics.Process
 $process.StartInfo=$Info
 try {
  if(!$process.Start()){throw 'Native process did not start'}
  # Drain both streams concurrently; native stderr is DATA, never a PowerShell
  # ErrorRecord. Read ExitCode before interpreting SQL/result evidence.
  $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
  $process.WaitForExit()
  $code=$process.ExitCode
  [pscustomobject]@{ExitCode=$code;Stdout=$stdout.GetAwaiter().GetResult();Stderr=$stderr.GetAwaiter().GetResult()}
 } finally {$process.Dispose()}
}
function Assert-CleanupRecoveryResult {
 param([int]$ExitCode,[string]$ResultText)
 if($ExitCode -ne 0){throw "Native cleanup failed with exit $ExitCode; no retry; inspect preserved stderr"}
 $records=@(foreach($line in $ResultText -split "`n") {
  if($line.Trim().StartsWith('{')){$line | ConvertFrom-Json -ErrorAction Stop}
 })
 $results=@($records|Where-Object{$_.record_type -ceq 'stage4b_write_cleanup'})
 if($results.Count -ne 1 -or $results[0].passed -isnot [bool] -or !$results[0].passed -or
  $results[0].metadata_restored -isnot [bool] -or !$results[0].metadata_restored -or
  $results[0].fixtures_absent -isnot [bool] -or !$results[0].fixtures_absent -or
  $results[0].proposed_objects_absent -isnot [bool] -or !$results[0].proposed_objects_absent) {
  throw 'Cleanup success evidence missing, ambiguous or false'
 }
}
