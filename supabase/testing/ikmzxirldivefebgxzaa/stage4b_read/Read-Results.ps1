function Read-Stage4BReadResult {
 param([string]$Path,[int]$ExitCode,[ValidateSet('runtime','cleanup_check')][string]$Phase)
 $records=@(); $bad=$false
 if (Test-Path -LiteralPath $Path) {
  foreach ($line in Get-Content -LiteralPath $Path -Encoding UTF8) {
   if ($line.StartsWith('{')) { try {$records+=($line | ConvertFrom-Json -ErrorAction Stop)} catch {$bad=$true} }
  }
 }
 if ($ExitCode -ne 0) { throw "TEST psql failed (exit $ExitCode); original SQL error/SQLSTATE printed above. Evidence: $Path. STOP; no retry." }
 if ($bad) { throw 'Malformed evidence JSON' }
 if (@($records | Where-Object {$_.record_type -eq 'failure'}).Count) { throw 'Failure record despite zero exit' }
 $test=if ($Phase -eq 'runtime') {'stage4b_read_runtime'} else {'stage4b_read_cleanup'}
 $results=@($records | Where-Object {$_.test -eq $test})
 if ($results.Count -ne 1 -or !$results[0].passed -or !$results[0].fixture_removed -or !$results[0].grant_rolled_back) { throw 'Missing/duplicate success or restoration result' }
 $expected=if ($Phase -eq 'runtime') {@('preflight','granted','tested','restored')} else {@('cleanup')}
 $checks=@($records | Where-Object {$_.record_type -eq 'metadata_check'})
 if ($checks.Count -ne $expected.Count) { throw 'Wrong metadata evidence count' }
 foreach ($name in $expected) {
  $one=@($checks | Where-Object {$_.phase -eq $name})
  if ($one.Count -ne 1) { throw 'Missing/duplicate metadata phase' }
  $shouldMatch=$name -notin @('granted','tested')
  if ([bool]$one[0].matches_expected -ne $shouldMatch -or $one[0].expected_md5 -cne '90a71db3b16ed177b3455f61a59343b2') { throw 'Wrong baseline/granted metadata expectation' }
 }
 if ($Phase -eq 'runtime') {
  $delta=@($records | Where-Object {$_.record_type -eq 'permission_delta'})
  if ($delta.Count -ne 2 -or @($delta | Where-Object {!$_.passed -or $_.effective_select_additions -ne 5 -or $_.direct_acl_additions -ne 5 -or $_.grantable}).Count) { throw 'Exact permission delta not proven' }
  $suite=@($records | Where-Object {$_.record_type -eq 'read_suite'})
  if ($suite.Count -ne 1 -or !$suite[0].passed -or $suite[0].cases -ne 14 -or $suite[0].assertions -ne 590 -or $suite[0].mode -cne 'SQL_ROLE_SIMULATION') { throw 'Read suite incomplete' }
  $cases=@($suite[0].case_results)
  if ($cases.Count -ne 14 -or @($cases | Select-Object -ExpandProperty 'case' -Unique).Count -ne 14 -or @($cases | Where-Object {!$_.passed -or $_.assertions -notin @(5,45)}).Count -gt 0) { throw 'Per-case evidence incomplete' }
  $boundary=@($records | Where-Object {$_.record_type -eq 'restricted_role_reads'})
  if ($boundary.Count -ne 1 -or !$boundary[0].passed -or $boundary[0].assertions -ne 15) { throw 'Anonymous/service-role restrictions not proven' }
  if (!(Select-String -LiteralPath $Path -Pattern '^STAGE4B_READ_ROLLBACK_ACKNOWLEDGED$' -Quiet)) { throw 'Rollback acknowledgement absent' }
 }
 $collision=@($records | Where-Object {$_.record_type -eq 'collision_check'})
 $count=if ($Phase -eq 'runtime') {2} else {1}
 if ($collision.Count -ne $count -or @($collision | Where-Object {!$_.passed}).Count) { throw 'Fixture cleanup/collision checks incomplete' }
 return $results[0]
}
