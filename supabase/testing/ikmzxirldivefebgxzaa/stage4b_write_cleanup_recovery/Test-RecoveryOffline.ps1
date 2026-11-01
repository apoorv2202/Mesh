# Offline fake native processes/dummy input only. Never invokes recovery launcher.
[CmdletBinding()]
param([string]$SourceRoot=$PSScriptRoot)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $SourceRoot 'Recovery-Support.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Helper parse failed'}
. ($ast.GetScriptBlock())
$script:checks=0
function Check([bool]$Value,[string]$Label){if(!$Value){throw "Offline assertion failed: $Label"};$script:checks++}
function Reject([scriptblock]$Block,[string]$Label){$caught=$false;try{& $Block}catch{$caught=$true};Check $caught $Label}
$pins=Join-Path $SourceRoot 'pins.json'
if(!(Test-Path -LiteralPath $pins)){throw 'Generate local preparation manifest before this offline test'}
$hash=(Get-FileHash -LiteralPath $pins -Algorithm SHA256).Hash.ToLowerInvariant()
Reject {Assert-RecoveryApproval -Approved $false -ReviewedHash $hash -ManifestPath $pins} 'missing explicit approval'
Reject {Assert-RecoveryApproval -Approved $true -ReviewedHash ('0'*64) -ManifestPath $pins} 'stale manifest'
Assert-RecoveryApproval -Approved $true -ReviewedHash $hash -ManifestPath $pins
Check $true 'valid approval checks only, no launcher'
$entryTokens=$null;$entryErrors=$null
$entryAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $SourceRoot 'Invoke-CleanupRecovery.ps1'),[ref]$entryTokens,[ref]$entryErrors)
if($entryErrors.Count){throw 'Entry syntax invalid'}
$entryGuards=@($entryAst.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and $n.Extent.Text -like "*throw 'Separate cleanup-recovery approval and exact newly reviewed manifest hash required'*"},$true))
Check ($entryGuards.Count -eq 1) 'one actual entry approval guard'
$entryGuard=[scriptblock]::Create($entryGuards[0].Extent.Text)
$manifestPath=$pins;$ReviewedManifestSha256=$hash;$ApproveCleanupRecovery=$false
Reject {& $entryGuard} 'actual entry denies missing approval'
$ApproveCleanupRecovery=$true;$ReviewedManifestSha256='0'*64
Reject {& $entryGuard} 'actual entry denies stale hash'
$ReviewedManifestSha256=$hash
& $entryGuard
Check $true 'actual entry guard only accepts correct approval/hash'
$m=Get-Content -LiteralPath $pins -Raw|ConvertFrom-Json
$ready=Get-Content -LiteralPath (Join-Path $SourceRoot 'readiness.json') -Raw|ConvertFrom-Json
Assert-RecoveryState -Manifest $m -Readiness $ready
Check $true 'closed persistent execution flags'
$old=$ready.test_ref;$ready.test_ref='khweikfvsnervfuswhon'
Reject {Assert-RecoveryState -Manifest $m -Readiness $ready} 'wrong project'
$ready.test_ref=$old;$ready.database_execution_authorized=$true
Reject {Assert-RecoveryState -Manifest $m -Readiness $ready} 'unexpected persistent authorization'
$ready.database_execution_authorized=$false
$temp=Join-Path ([IO.Path]::GetTempPath()) ('VaderRecoveryOffline_'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($temp)
try {
 Reject {Assert-NewRecoveryDirectory -Path $temp} 'existing evidence directory'
 $reservation=Join-Path $temp 'synthetic-reservation'
 $h=[IO.File]::Open($reservation,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{Reject {$second=[IO.File]::Open($reservation,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$second.Dispose()} 'atomic reservation rejects duplicate'}finally{$h.Dispose()}
} finally {
 if(Test-Path -LiteralPath (Join-Path $temp 'synthetic-reservation')){[IO.File]::Delete((Join-Path $temp 'synthetic-reservation'))}
 [IO.Directory]::Delete($temp)
}
$result='{"record_type":"stage4b_write_cleanup","passed":true,"metadata_restored":true,"fixtures_absent":true,"proposed_objects_absent":true}'
foreach($reason in @('synthetic missing credentials','synthetic failed authentication','synthetic SQL failure')) {
 $info=New-Object Diagnostics.ProcessStartInfo
 $info.FileName=Join-Path ([Environment]::GetFolderPath('System')) 'cmd.exe'
 $info.UseShellExecute=$false;$info.CreateNoWindow=$true
 $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $info.Arguments='/d /c "echo '+$reason+' 1>&2 & exit /b 2"'
 $captured=Invoke-RecoveryCapturedProcess -Info $info
 Check ($captured.ExitCode -eq 2) 'nonzero native exit retained'
 Check ($captured.Stderr.Contains($reason)) 'stderr retained as data despite ErrorActionPreference Stop'
 Reject {Assert-CleanupRecoveryResult -ExitCode $captured.ExitCode -ResultText $result} 'nonzero exit overrides success-shaped JSON'
}
Reject {Assert-CleanupRecoveryResult -ExitCode 0 -ResultText ''} 'empty evidence rejected'
Reject {Assert-CleanupRecoveryResult -ExitCode 0 -ResultText ($result+"`n"+$result)} 'ambiguous evidence rejected'
Assert-CleanupRecoveryResult -ExitCode 0 -ResultText $result
Check $true 'single successful result accepted in memory'
# Dummy transport test, not a password or a test-project connection. This does
# not claim to establish psql CONIN$ behavior in the user's interactive terminal.
$info=New-Object Diagnostics.ProcessStartInfo
$info.FileName=Join-Path ([Environment]::GetFolderPath('System')) 'cmd.exe'
$info.UseShellExecute=$false;$info.CreateNoWindow=$true
$info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
$info.Arguments='/d /v:on /c "set /p VADER_DUMMY= & if !VADER_DUMMY!==DUMMY_ONLY_123 (echo dummy-input-ok) else (exit /b 4)"'
$dummy=New-Object Diagnostics.Process;$dummy.StartInfo=$info
try {
 $null=$dummy.Start();$dummy.StandardInput.WriteLine('DUMMY_ONLY_123');$dummy.StandardInput.Close()
 $dummyOut=$dummy.StandardOutput.ReadToEnd();$dummyErr=$dummy.StandardError.ReadToEnd();$dummy.WaitForExit()
 Check ($dummy.ExitCode -eq 0 -and $dummyOut.Contains('dummy-input-ok')) 'dummy-only input transport'
} finally {$dummy.Dispose()}
if(!('VaderRecovery.ConsoleProbe' -as [type])){Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $SourceRoot 'ConsoleProbe.cs')))}
$available=[VaderRecovery.ConsoleProbe]::Available()
if(!$available){Reject {Assert-InteractiveRecoveryConsole -ConsoleSource (Join-Path $SourceRoot 'ConsoleProbe.cs')} 'headless console fails before attempt'}
Write-Output "PASS: $script:checks offline checks. Native exit/stderr captured; dummy input only; real console available=$available. No psql, SQL, recovery launcher or attempt directory invoked."
