param(
    [string]$OutputPath = '',
    [ValidateSet('agents', 'rules')][string]$Mode = 'agents',
    [ValidateRange(1, 16)][int]$Processes = 8,
    [ValidateRange(1, 128)][int]$Workers = 32,
    [Nullable[long]]$Seed = $null,
    [switch]$Full,
    [string]$PythonExecutable = 'python'
)

$ErrorActionPreference = 'Stop'
$item3Workspace = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $OutputPath) {
    $OutputPath = Join-Path $item3Workspace ('results/item3_certification_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
} elseif (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
    $OutputPath = Join-Path $item3Workspace $OutputPath
}
$item3Output = [System.IO.Path]::GetFullPath($OutputPath)
Push-Location $item3Workspace
try {
    $item3Watch = [System.Diagnostics.Stopwatch]::StartNew()
    $selectionArgs = @()
    if ($null -ne $Seed) { $selectionArgs += @('--seed', $Seed) }
    if ($Full) { $selectionArgs += '--full' }
    & $PythonExecutable -X utf8 tools/item3/run_item3_certification.py --mode $Mode --processes $Processes --workers $Workers --output $item3Output @selectionArgs
    $item3Exit = $LASTEXITCODE
    $item3Watch.Stop()
    $item3ResultPath = Join-Path $item3Output 'certification_result.json'
    if (-not (Test-Path -LiteralPath $item3ResultPath -PathType Leaf)) {
        throw "No complete certification report was produced: $item3Output"
    }
    $item3Result = Get-Content -LiteralPath $item3ResultPath -Raw -Encoding utf8 | ConvertFrom-Json
    $item3WallPassed = $item3Result.time_requirement_met -and ($item3Watch.Elapsed.TotalSeconds -lt $item3Result.time_limit_seconds)
    @{
        elapsed_seconds = $item3Watch.Elapsed.TotalSeconds
        exit_code = $item3Exit
        includes_python_startup_and_exit = $true
        time_requirement_met = $item3WallPassed
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $item3Output 'process_wall_time.json') -Encoding utf8
    Write-Host ('Completed: {0}/{1} files; {2} components; errors: {3}' -f $item3Result.completed_cases, $item3Result.cases, $item3Result.components, $item3Result.execution_errors)
    Write-Host ('End-to-end wall time: {0:N2} seconds / {1}; requirement met: {2}' -f $item3Watch.Elapsed.TotalSeconds, $item3Result.time_limit_seconds, $item3WallPassed)
    Write-Host ('Expected-list precision: {0}%; criterion: {1}' -f $item3Result.full_output_precision_percent, $item3Result.precision_criterion_status)
    Write-Host ('Report: ' + $item3ResultPath)
    if (-not $item3WallPassed) { $item3Exit = 2 }
} finally {
    Pop-Location
}
exit $item3Exit
