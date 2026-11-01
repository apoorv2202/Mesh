# READ-ONLY preflight only. No Bootstrap action, SQL mutations or secret files.
$ErrorActionPreference = 'Stop'
$resultPath = Join-Path $PSScriptRoot 'preflight_result.json'
$statusPath = Join-Path $PSScriptRoot 'preflight_status.json'
Write-Host 'VADER READ-ONLY TEST preflight: ikmzxirldivefebgxzaa' -ForegroundColor Cyan
Write-Host 'Protected production is excluded. No bootstrap/migration will be run.'
Write-Host 'Enter the TEST database password only when psql prompts. It is not saved.'
try {
    $launcher = Join-Path $PSScriptRoot 'Invoke-TestDatabase.ps1'
    $lines = & $launcher -Action ConnectionCheck -Mode SessionPooler `
        -TestHost 'aws-0-eu-west-1.pooler.supabase.com' `
        -RootCertificate 'C:\Users\APOORV\Downloads\prod-ca-2021.crt'
    $result = $null
    foreach ($line in $lines) {
        $candidate = ([string]$line).Trim()
        if ($candidate.StartsWith('{') -and $candidate.EndsWith('}')) {
            try {
                $parsed = $candidate | ConvertFrom-Json
                if ($parsed.client_asserted_test_ref -eq 'ikmzxirldivefebgxzaa' -and $parsed.database) {
                    $result = $parsed
                }
            } catch { }
        }
    }
    if ($null -eq $result) { throw 'No expected JSON result received' }
    $result | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $resultPath -Encoding UTF8
    @{status='success'; target='ikmzxirldivefebgxzaa'; read_only=$true; result_file='preflight_result.json'} |
        ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding UTF8
    Write-Host 'Read-only preflight complete. Only metadata JSON was saved.' -ForegroundColor Green
} catch {
    # Do not persist raw connection/exception strings or any entered credentials.
    @{status='failed'; target='ikmzxirldivefebgxzaa'; read_only=$true; message='Preflight failed; inspect the local terminal. No raw exception or credential was saved.'} |
        ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding UTF8
    Write-Host 'Read-only preflight failed. No credentials or raw error were saved.' -ForegroundColor Yellow
}
Write-Host 'Finished. This terminal may be closed.'
