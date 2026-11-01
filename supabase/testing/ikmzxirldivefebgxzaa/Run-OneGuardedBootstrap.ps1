# Explicitly authorized ONE TEST attempt. Run in your OWN interactive PowerShell.
# No password variables/files, SQL edits, retry, seed, migration 01/02 or production.
$ErrorActionPreference = 'Stop'
$target = 'ikmzxirldivefebgxzaa'
$testHost = 'aws-0-eu-west-1.pooler.supabase.com'
$testUser = 'postgres.ikmzxirldivefebgxzaa'
$caPath = 'C:\Users\APOORV\Downloads\prod-ca-2021.crt'
$psqlPath = 'C:\Program Files\PostgreSQL\18\bin\psql.exe'
$reviewedHash = '02b3dc6c26021227cef1a67b2591e0277b1d2c8b0ba059cdcb92d62599eb5fc4'
$markerPath = Join-Path $PSScriptRoot 'bootstrap_attempt.json'
$statusPath = Join-Path $PSScriptRoot 'bootstrap_execution_result.json'
$rawPath = Join-Path $PSScriptRoot 'post_bootstrap_verification_raw.txt'
$jsonPath = Join-Path $PSScriptRoot 'post_bootstrap_verification.json'
$pins = @{
    'bootstrap_test_only.sql' = $reviewedHash
    'fidelity_manifest.json' = 'df0e1beb81cfec499bee610680b2c623525232d20d3e2af25f146141dc97a8f6'
    'Invoke-TestDatabase.ps1' = '209884826ac72eea27878d04a88ca28e6b828058c39f1f6b91420e5689c00039'
    'target_guard.psql' = 'd43d44ba5bcd394616c860e14e6aab671a5f8df354ccf7993380fc512ede5189'
    'verify_schema.sql' = '76c8f32c54193985c59fc8c4e0b65f282e4b888b28fb700b0e9341d89eee8b64'
    '..\..\inspection\master_inspection.sql' = 'c2910974e4cf17087ccbed7831c0eb53819c78f535e147876735ce3cb44a478b'
    'preflight_result.json' = 'b029522ac959950eccf9f61a5bc19be799e869f1e0df40175e458612c8dc5e72'
}
if (Test-Path -LiteralPath $markerPath) { throw 'Attempt marker exists. STOP: no retry is authorized; review recorded outcome first.' }
foreach ($item in $pins.GetEnumerator()) {
    $path = Join-Path $PSScriptRoot $item.Key
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Reviewed artifact missing: $($item.Key)" }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $item.Value) {
        throw "Reviewed artifact changed: $($item.Key). No SQL will run."
    }
}
$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fidelity_manifest.json') -Raw | ConvertFrom-Json
if ($manifest.allowed_test_ref -cne $target -or $manifest.bootstrap_sha256 -cne $reviewedHash) { throw 'Manifest/TEST guard failed' }
if (!(Test-Path -LiteralPath $psqlPath -PathType Leaf)) { throw 'Reviewed psql client missing' }
if (!(Test-Path -LiteralPath $caPath -PathType Leaf)) { throw 'Trusted CA file missing' }
if ((Get-FileHash -LiteralPath $caPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne '700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7') { throw 'Reviewed CA bytes changed' }
$ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($caPath)
$basic = $ca.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' }
if (!$basic -or !$basic.CertificateAuthority -or $ca.HasPrivateKey -or $ca.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or $ca.NotAfter.ToUniversalTime() -lt [DateTime]::UtcNow) { throw 'CA validation failed' }

function Save-Outcome([string]$Outcome, [string]$Phase, [bool]$Committed, [bool]$Verified) {
    @{target=$target; bootstrap_sha256=$reviewedHash; outcome=$Outcome; phase=$Phase;
      bootstrap_commit_acknowledged=$Committed; structural_verification_passed=$Verified;
      recorded_at_utc=[DateTime]::UtcNow.ToString('o'); migration_01_executed=$false;
      migration_02_executed=$false; production_accessed=$false} |
      ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding UTF8
}

# Atomic local reservation: a second/concurrent invocation cannot consume another
# attempt. Marker is never removed automatically, even on authentication failure.
$stream = [IO.File]::Open($markerPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try {
    $writer = New-Object IO.StreamWriter($stream)
    $writer.WriteLine((@{target=$target; bootstrap_sha256=$reviewedHash;
      reserved_at_utc=[DateTime]::UtcNow.ToString('o'); max_bootstrap_attempts=1} | ConvertTo-Json -Compress))
    $writer.Flush()
} finally { $stream.Dispose() }

$committed = $false
$phase = 'bootstrap'
try {
    Save-Outcome 'started' $phase $false $false
    Write-Host 'ONE guarded TEST bootstrap attempt. Enter only the TEST password at psql prompt.' -ForegroundColor Cyan
    # No stdout capture/pipeline around psql: the interactive console owns stdin.
    & (Join-Path $PSScriptRoot 'Invoke-TestDatabase.ps1') -Action Bootstrap -ApproveBootstrap `
        -Mode SessionPooler -TestHost $testHost -RootCertificate $caPath
    $committed = $true
    Save-Outcome 'bootstrap_committed' $phase $true $false

    # Separate READ-ONLY connection. psql --output redirects ONLY metadata output,
    # not password input. Credentials are prompted again and never persisted.
    $phase = 'read_only_verification'
    Write-Host 'Bootstrap committed. Enter TEST password again for READ-ONLY verification.' -ForegroundColor Cyan
    $names = @('PGHOST','PGHOSTADDR','PGUSER','PGPORT','PGDATABASE','PGSERVICE','PGSERVICEFILE',
        'PGPASSWORD','PGPASSFILE','PGOPTIONS','PGSSLMODE','PGSSLROOTCERT','PGAPPNAME',
        'PGCONNECT_TIMEOUT','PGSSLCERT','PGSSLKEY','PGSSLCRL','PGSSLCRLDIR','PGREQUIRESSL')
    $saved = @{}
    foreach ($name in $names) {
        $saved[$name] = [Environment]::GetEnvironmentVariable($name,'Process')
        [Environment]::SetEnvironmentVariable($name,$null,'Process')
    }
    try {
        $env:PGHOST=$testHost; $env:PGUSER=$testUser; $env:PGPORT='5432'; $env:PGDATABASE='postgres'
        $env:PGSSLMODE='verify-full'; $env:PGSSLROOTCERT=$caPath; $env:PGCONNECT_TIMEOUT='10'
        $env:PGAPPNAME='mesh-vader-post-bootstrap-read-only'
        $env:PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=60000 -c lock_timeout=5000'
        & $psqlPath -X -W -q -A -t --host $testHost --port 5432 --username $testUser `
            --dbname postgres --set ON_ERROR_STOP=1 --set "vader_test_ref=$target" `
            --file (Join-Path $PSScriptRoot 'verify_schema.sql') --output $rawPath
        if ($LASTEXITCODE -ne 0) { throw 'Read-only verification connection/query failed' }
    } finally {
        foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name,$saved[$name],'Process') }
    }
    $verification = Get-Content -LiteralPath $rawPath -Raw | ConvertFrom-Json
    $verification | ConvertTo-Json -Depth 80 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    if ($verification.'01_inventory'.inspection.actual_count_including_partition_children -ne 18 `
        -or @($verification.'01_inventory'.inspection.missing_expected).Count -ne 0 `
        -or @($verification.'01_inventory'.inspection.unexpected_tables).Count -ne 0 `
        -or @($verification.'02_columns'.inspection).Count -ne 165 `
        -or @($verification.'03_constraints'.inspection).Count -ne 85 `
        -or @($verification.'04_indexes'.inspection).Count -ne 46 `
        -or @($verification.'10_policies'.inspection).Count -ne 18) { throw 'Post-bootstrap structural count mismatch' }
    $rls = @($verification.'09_rls_status'.inspection)
    if ($rls.Count -ne 18 -or @($rls | Where-Object { !$_.rls_enabled -or $_.rls_forced }).Count -ne 0) { throw 'RLS verification mismatch' }
    Save-Outcome 'bootstrap_and_structural_verification_succeeded' $phase $true $true
    Write-Host 'STOP: bootstrap and read-only metadata collection succeeded. Migration 01/02 were NOT run.' -ForegroundColor Green
    Write-Host 'Return bootstrap_execution_result.json and post_bootstrap_verification.json for detailed review.'
} catch {
    # Unknown network/COMMIT outcomes must not be called confirmed rollbacks.
    $outcome = if ($committed) { 'bootstrap_committed_verification_failed' } else { 'bootstrap_failed_or_outcome_unknown_no_retry' }
    Save-Outcome $outcome $phase $committed $false
    Write-Host 'STOP. Do not rerun or delete the attempt marker. Inspect the terminal error and return the non-secret status.' -ForegroundColor Yellow
    Write-Host 'A SQL failure before COMMIT rolls back on client disconnect; a lost COMMIT acknowledgement requires review, not a retry.'
    throw
}
