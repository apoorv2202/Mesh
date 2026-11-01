# Exercise ONLY the existing approval IF statement, extracted from its AST.
# The launcher, Runtime, CleanupCheck and every connection path are NEVER invoked.
[CmdletBinding()]
param([string]$SourceRoot=$PSScriptRoot)
$ErrorActionPreference='Stop'
$source=Join-Path $SourceRoot 'Invoke-WriteRollback.ps1'
$tokens=$null;$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Launcher syntax invalid'}
$guards=@($ast.FindAll({param($node)
 $node -is [System.Management.Automation.Language.IfStatementAst] -and
 $node.Extent.Text -like "*throw 'Separate authorization and independently reviewed pins hash required'*"
},$true))
if($guards.Count -ne 1){throw 'Approval guard missing/ambiguous'}
# Exact structural text protects this test from evaluating extra launcher content.
$reviewed="if (!`$ApproveTestRollback -or `$ReviewedPinsSha256 -cne (Get-FileHash -LiteralPath `$pinPath -Algorithm SHA256).Hash.ToLowerInvariant()) { throw 'Separate authorization and independently reviewed pins hash required' }"
if($guards[0].Extent.Text -cne $reviewed){throw 'Approval guard changed; independent review required'}
$guard=[scriptblock]::Create($guards[0].Extent.Text)
$pinPath=Join-Path $SourceRoot 'pins.json'
$currentHash=(Get-FileHash -LiteralPath $pinPath -Algorithm SHA256).Hash.ToLowerInvariant()
$n=0
foreach($actionLabel in @('Runtime','CleanupCheck')) {
 foreach($eligibility in @($false,$true)) {
  $ready=@{authorizable=$eligibility;database_execution_authorized=$false}
  foreach($case in @(
   @{approved=$false;hash='';allowed=$false},
   @{approved=$false;hash=$currentHash;allowed=$false},
   @{approved=$true;hash='';allowed=$false},
   @{approved=$true;hash=('0'*64);allowed=$false},
   @{approved=$true;hash=$currentHash;allowed=$true}
  )) {
   $ApproveTestRollback=$case.approved;$ReviewedPinsSha256=$case.hash;$rejected=$false
   try { & $guard } catch {
    if($_.Exception.Message -cne 'Separate authorization and independently reviewed pins hash required'){throw}
    $rejected=$true
   }
   if((!$rejected) -ne $case.allowed){throw "Approval check failed: $actionLabel eligibility=$eligibility"}
   $n++
  }
 }
}
Write-Output "PASS: $n isolated approval-guard cases. Eligibility alone denied; missing approvals and stale hashes denied. No launcher or execution branch invoked."
