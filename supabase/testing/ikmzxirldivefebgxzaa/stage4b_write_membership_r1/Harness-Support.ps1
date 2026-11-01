# Definitions only. Import cannot start a process or connection.
function Assert-FreshApproval {
 param([string]$Action,[bool]$RuntimeApproval,[bool]$CleanupApproval,[string]$Hash,[string]$Manifest)
 if($Action -cnotin @('Runtime','CleanupCheck') -or
 ($Action -ceq 'Runtime' -and (!$RuntimeApproval -or $CleanupApproval)) -or
 ($Action -ceq 'CleanupCheck' -and (!$CleanupApproval -or $RuntimeApproval)) -or
 $Hash -cnotmatch '^[0-9a-f]{64}$' -or
 $Hash -cne (Get-FileHash -LiteralPath $Manifest -Algorithm SHA256).Hash.ToLowerInvariant()) {
  throw 'Separate action-specific approval and exact reviewed fresh manifest required'
 }
}
function Assert-FreshState {
 param($Manifest,$Readiness)
 if(@($Manifest.PSObject.Properties.Name|Where-Object{$_ -notin @('test_ref','scope','revision','source_manifest_sha256','execution_authorized','files')}).Count -or
 @($Readiness.PSObject.Properties.Name|Where-Object{$_ -notin @('test_ref','scope','execution_authorized','database_execution_authorized')}).Count -or
 $Manifest.test_ref -cne 'ikmzxirldivefebgxzaa' -or $Readiness.test_ref -cne 'ikmzxirldivefebgxzaa' -or
 $Manifest.scope -cne 'membership_fix_rollback_and_fresh_cleanup' -or $Readiness.scope -cne $Manifest.scope -or
 $Manifest.revision -cne 'membership_r1' -or
 $Manifest.source_manifest_sha256 -cne '8fa4f4292932e6a2a05f846d93e442c6a4fca372018b071620bf285a623450d3' -or
 $Manifest.execution_authorized -isnot [bool] -or $Manifest.execution_authorized -or
 $Readiness.execution_authorized -isnot [bool] -or $Readiness.execution_authorized -or
 $Readiness.database_execution_authorized -isnot [bool] -or $Readiness.database_execution_authorized) {throw 'Invalid fresh TEST preparation state'}
}
function Assert-FreshSlot {
 param([string]$Path)
 if(Test-Path -LiteralPath $Path){throw 'Prior fresh evidence exists; no overwrite or retry'}
}
function Assert-FreshConsole {
 param([string]$Source)
 if($Host.Name -ne 'ConsoleHost' -or [Console]::IsInputRedirected -or [Console]::IsOutputRedirected){throw 'Real interactive ConsoleHost required before reserving attempt'}
 if(!('VaderRecovery.ConsoleProbe' -as [type])){Add-Type -TypeDefinition ([IO.File]::ReadAllText($Source))}
 if(![VaderRecovery.ConsoleProbe]::Available()){throw 'Native console unavailable; no attempt started'}
}
function Invoke-FreshNative {
 param([Diagnostics.ProcessStartInfo]$Info)
 if($Info.UseShellExecute -or !$Info.RedirectStandardOutput -or !$Info.RedirectStandardError -or $Info.RedirectStandardInput){throw 'Invalid native console/capture settings'}
 $p=New-Object Diagnostics.Process;$p.StartInfo=$Info;$started=$false
 try {
  if(!$p.Start()){throw 'Native process did not start'};$started=$true
  $out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync()
  $p.WaitForExit();$code=$p.ExitCode
  [pscustomobject]@{ExitCode=$code;Stdout=$out.GetAwaiter().GetResult();Stderr=$err.GetAwaiter().GetResult()}
 } finally {
  # Ordinary cancellation/exception closes this client; a host crash may bypass
  # finally. Fresh CleanupCheck independently refuses any still-running psql.
  if($started -and !$p.HasExited){$p.Kill();$p.WaitForExit()}
  $p.Dispose()
 }
}
function Assert-FreshResult {
 param([string]$Action,[int]$ExitCode,[string]$Text)
 if($ExitCode -ne 0){throw "Native $Action failed with exit $ExitCode; inspect preserved stderr; no retry"}
 $records=@(foreach($line in $Text -split "`n"){if($line.Trim().StartsWith('{')){$line|ConvertFrom-Json -ErrorAction Stop}})
 $kind=if($Action -ceq 'Runtime'){'stage4b_write_result'}elseif($Action -ceq 'CleanupCheck'){'stage4b_write_cleanup'}else{throw 'Invalid result action'}
 $results=@($records|Where-Object{$_.record_type -ceq $kind})
 if($results.Count -ne 1){throw 'Missing/ambiguous final result'}
 foreach($field in @('passed','metadata_restored','fixtures_absent')) {
  if($results[0].$field -isnot [bool] -or !$results[0].$field){throw 'Incomplete/false restoration result'}
 }
 $metadata=@($records|Where-Object{$_.record_type -ceq 'metadata_check' -and $_.phase -ceq $(if($Action -ceq 'Runtime'){'restored'}else{'fresh_cleanup'})})
 if($metadata.Count -ne 1 -or $metadata[0].matches_expected -isnot [bool] -or !$metadata[0].matches_expected -or
 $metadata[0].expected_md5 -cne '90a71db3b16ed177b3455f61a59343b2' -or $metadata[0].comparison_md5 -cne $metadata[0].expected_md5){throw 'Restored metadata evidence incomplete'}
 $collision=@($records|Where-Object{$_.record_type -ceq 'collision_check'})
 if(!$collision.Count){throw 'Collision checks missing'}
 foreach($check in $collision){
  if($check.passed -isnot [bool] -or !$check.passed -or @($check.counts).Count -ne 10 -or @($check.counts|Where-Object{$_.collision_count -ne 0}).Count){throw 'Fixture collision/residue evidence rejected'}
 }
 if($Action -ceq 'Runtime') {
  if(@($Text -split "`n"|Where-Object{$_.TrimEnd("`r") -ceq 'STAGE4B_WRITE_ROLLBACK_ACKNOWLEDGED'}).Count -ne 1){throw 'Exactly one rollback acknowledgement required'}
  $asserts=@($records|Where-Object{$_.record_type -ceq 'write_assertions'})
  if($asserts.Count -ne 1 -or $asserts[0].human -ne 46 -or $asserts[0].membership_denials -ne 20 -or $asserts[0].fk_denials -ne 2 -or $asserts[0].audit_fault -isnot [bool] -or !$asserts[0].audit_fault){throw 'Incomplete human/FK/audit assertions'}
  $acl=@($records|Where-Object{$_.record_type -ceq 'acl_baseline'})
  if($acl.Count -ne 1 -or $acl[0].md5 -cne 'e4e671b562707df52adc76c3c26e14af'){throw 'Original ACL baseline mismatch'}
  $deltas=@($records|Where-Object{$_.record_type -ceq 'exact_acl_delta'})
  if($deltas.Count -ne 2){throw 'Both installed/tested exact ACL checks required'}
  foreach($delta in $deltas){if($delta.passed -isnot [bool] -or !$delta.passed -or @($delta.unexpected).Count -or @($delta.missing).Count){throw 'Exact ACL delta rejected'}}
 } elseif($results[0].proposed_objects_absent -isnot [bool] -or !$results[0].proposed_objects_absent){throw 'Proposed object absence missing'}
}
function Assert-CleanupReservation {
 param($Reservation,[string]$Hash)
 if($Reservation.action -cne 'Runtime' -or $Reservation.test_ref -cne 'ikmzxirldivefebgxzaa' -or
 $Reservation.manifest_sha256 -cne $Hash -or $Reservation.source_manifest_sha256 -cne '8fa4f4292932e6a2a05f846d93e442c6a4fca372018b071620bf285a623450d3') {throw 'Missing/invalid corrected Runtime reservation'}
 # No PASS prerequisite: failed, missing or interrupted final receipts do not
 # prevent a separately approved read-only restoration check.
}
