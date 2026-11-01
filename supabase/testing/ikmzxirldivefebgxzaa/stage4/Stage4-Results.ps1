# Pure local evidence parser, independently testable without invoking psql.
function Read-Stage4Result {
 param([string]$Path,[int]$ExitCode,[ValidateSet('runtime','cleanup_check')][string]$Phase)
 $records=@()
 $parseFailed=$false
 if (Test-Path -LiteralPath $Path) {
  foreach ($line in Get-Content -LiteralPath $Path -Encoding UTF8) {
   if ($line.StartsWith('{')) {
    try { $records+=($line | ConvertFrom-Json -ErrorAction Stop) } catch { $parseFailed=$true }
   }
  }
 }
 # Native exit status has priority over success-output parsing. Never mask SQL failure.
 if ($ExitCode -ne 0) {
  $lastFailure=@($records | Where-Object {$_.record_type -eq 'failure'} | Select-Object -Last 1)
  $detail=if ($lastFailure.Count -eq 1) { $lastFailure[0] | ConvertTo-Json -Compress -Depth 10 } else {'See original PostgreSQL error/SQLSTATE printed above; no structured failure was produced.'}
  throw "TEST psql failed (exit $ExitCode). $detail Evidence: $Path. STOP; no retry."
 }
 if ($parseFailed) { throw "TEST output JSON is malformed. Evidence: $Path. STOP; no retry." }
 if (@($records | Where-Object {$_.record_type -eq 'failure'}).Count -gt 0) { throw "Failure diagnostic despite zero client exit. Evidence: $Path. STOP." }
 $expected=if ($Phase -eq 'runtime') {'stage4_runtime'} else {'stage4_cleanup'}
 $results=@($records | Where-Object {$_.test -eq $expected})
 if ($results.Count -ne 1) { throw "No unique $expected success result after zero psql exit. Evidence: $Path. STOP; outcome unverified." }
 $result=$results[0]
 if (!$result.passed -or !$result.fixture_removed) { throw 'Assertion/cleanup success evidence missing' }
 $checks=@($records | Where-Object {$_.record_type -eq 'metadata_check'})
 $expectedPhases=if ($Phase -eq 'runtime') {@('preflight','restored')} else {@('cleanup')}
 if ($checks.Count -ne $expectedPhases.Count) { throw 'Metadata-check evidence count mismatch' }
 foreach ($name in $expectedPhases) {
  $matching=@($checks | Where-Object {$_.phase -eq $name})
  if ($matching.Count -ne 1 -or !$matching[0].matches_expected) { throw "Metadata-check evidence failed: $name" }
 }
 if ($Phase -eq 'runtime' -and !(Select-String -LiteralPath $Path -Pattern '^STAGE4_ROLLBACK_ACKNOWLEDGED$' -Quiet)) { throw 'Rollback acknowledgement missing; stop for read-only outcome review' }
 return $result
}
