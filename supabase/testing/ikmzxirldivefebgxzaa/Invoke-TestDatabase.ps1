# Preparation artifact. Nothing runs until explicitly invoked after approval.
# Default action is LOCAL --version only. No arbitrary SQL/file/URI parameter.
[CmdletBinding()]
param(
    [ValidateSet('ValidateClient','ConnectionCheck','VerifySchema','Bootstrap')]
    [string]$Action = 'ValidateClient',
    [ValidateSet('SessionPooler','Direct')][string]$Mode = 'SessionPooler',
    [string]$TestHost,
    [string]$RootCertificate,
    [switch]$ApproveBootstrap
)
$ErrorActionPreference = 'Stop'
$psqlPath = 'C:\Program Files\PostgreSQL\18\bin\psql.exe'
$testRef = 'ikmzxirldivefebgxzaa'
$protectedRef = 'khweikfvsnervfuswhon'
if ($testRef -eq $protectedRef) { throw 'TEST identity configuration invalid' }
if (!(Test-Path -LiteralPath $psqlPath -PathType Leaf)) { throw 'Expected psql executable missing' }
if ($Action -eq 'ValidateClient') {
    & $psqlPath --version
    exit $LASTEXITCODE
}
if ($Action -eq 'Bootstrap' -and !$ApproveBootstrap) { throw 'Bootstrap needs explicit human approval and -ApproveBootstrap' }
if ($ApproveBootstrap -and $Action -ne 'Bootstrap') { throw 'Bootstrap approval cannot accompany a read-only action' }
if ($Mode -eq 'Direct') {
    if ($TestHost -cne "db.$testRef.supabase.co") { throw 'Direct host must be the exact TEST project host' }
    $dbUser = 'postgres'
} else {
    if ($TestHost -cnotmatch '^[-a-z0-9]+\.pooler\.supabase\.com$') { throw 'Use hostname only from TEST Connect / Session pooler panel' }
    $dbUser = "postgres.$testRef"
}
if ($TestHost.Contains($protectedRef) -or $dbUser.Contains($protectedRef)) { throw 'Production route refused' }
if ([string]::IsNullOrWhiteSpace($RootCertificate) -or !(Test-Path -LiteralPath $RootCertificate -PathType Leaf)) { throw 'TLS root certificate required' }
$RootCertificate = (Resolve-Path -LiteralPath $RootCertificate).Path
$fileName = switch ($Action) {
    'ConnectionCheck' { 'connection_check.sql' }
    'VerifySchema' { 'verify_schema.sql' }
    'Bootstrap' { 'bootstrap_test_only.sql' }
}
$sqlFile = Join-Path $PSScriptRoot $fileName
if (!(Test-Path -LiteralPath $sqlFile -PathType Leaf)) { throw 'Prepared SQL file missing' }
if ($Action -eq 'Bootstrap') {
    $manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fidelity_manifest.json') -Raw | ConvertFrom-Json
    $actualHash = (Get-FileHash -LiteralPath $sqlFile -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($manifest.allowed_test_ref -cne $testRef -or $actualHash -cne $manifest.bootstrap_sha256) { throw 'Bootstrap hash/target mismatch; review regeneration before execution' }
}
# Sanitize inherited libpq routing/credentials/options and restore afterwards.
$names = @('PGHOST','PGHOSTADDR','PGUSER','PGPORT','PGDATABASE','PGSERVICE','PGSERVICEFILE',
    'PGPASSWORD','PGPASSFILE','PGOPTIONS','PGSSLMODE','PGSSLROOTCERT','PGAPPNAME',
    'PGCONNECT_TIMEOUT','PGSSLCERT','PGSSLKEY','PGSSLCRL','PGSSLCRLDIR','PGREQUIRESSL')
$saved = @{}
foreach ($name in $names) {
    $saved[$name] = [Environment]::GetEnvironmentVariable($name,'Process')
    [Environment]::SetEnvironmentVariable($name,$null,'Process')
}
try {
    $env:PGHOST = $TestHost
    $env:PGUSER = $dbUser
    $env:PGPORT = '5432'
    $env:PGDATABASE = 'postgres'
    $env:PGSSLMODE = 'verify-full'
    $env:PGSSLROOTCERT = $RootCertificate
    $env:PGAPPNAME = 'mesh-vader-disposable-bootstrap'
    $env:PGCONNECT_TIMEOUT = '10'
    $readOnly = if ($Action -eq 'Bootstrap') { 'off' } else { 'on' }
    $env:PGOPTIONS = "-c default_transaction_read_only=$readOnly -c statement_timeout=60000 -c lock_timeout=5000 -c idle_in_transaction_session_timeout=60000"
    $psqlArgs = @('-X','-W','--host',$TestHost,'--port','5432','--username',$dbUser,
        '--dbname','postgres','--set','ON_ERROR_STOP=1','--set',"vader_test_ref=$testRef")
    if ($Action -eq 'Bootstrap') { $psqlArgs += @('--set',"vader_bootstrap_approved=$testRef") }
    $psqlArgs += @('--file',$sqlFile)
    & $psqlPath @psqlArgs
    $resultCode = $LASTEXITCODE
    if ($resultCode -ne 0) { throw "TEST psql failed (exit $resultCode); stop and review. No automatic retries or migration follow-up." }
} finally {
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name,$saved[$name],'Process') }
}
