# Manual cleanup: four explicitly retired adapter directories, including checkpoints.
# Execute from PowerShell after reviewing this list. Active adapters are not targets.
$ErrorActionPreference = 'Stop'
$workspaceTask = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$modelsTask = (Resolve-Path -LiteralPath (Join-Path $workspaceTask 'models')).Path
$retiredTask = @(
    'cve-conditions-qwen3-8b-v1',
    'source-evidence-qwen3-8b-v1',
    'operation-questions-qwen3-8b-curriculum-v2',
    'operation-assessment-qwen3-8b-curriculum-v2'
)
$targetsTask = @()
foreach ($nameTask in $retiredTask) {
    $candidateTask = Join-Path $modelsTask $nameTask
    if (-not (Test-Path -LiteralPath $candidateTask)) { continue }
    $resolvedTask = (Resolve-Path -LiteralPath $candidateTask).Path
    if ((Split-Path -Parent $resolvedTask) -ne $modelsTask) { throw "Unexpected target: $resolvedTask" }
    $entryTask = Get-Item -LiteralPath $resolvedTask
    if (-not $entryTask.PSIsContainer -or ($entryTask.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Unexpected target type: $resolvedTask" }
    if (Get-ChildItem -LiteralPath $resolvedTask -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) { throw "Linked child found: $resolvedTask" }
    $targetsTask += $resolvedTask
}
foreach ($targetTask in $targetsTask) {
    Remove-Item -LiteralPath $targetTask -Recurse -Force
    Write-Output "Removed: $targetTask"
}
Write-Output 'Cleanup complete. The six active adapters and historical reports were retained.'
