# Execute manually after reviewing results/cleanup_20261101.json.
# Supports -WhatIf. Does not target models, datasets, sources or final reports.
[CmdletBinding(SupportsShouldProcess=$true)]
param()
$ErrorActionPreference = 'Stop'
$workspaceRoot = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path.TrimEnd('\')
$planPath = Join-Path $workspaceRoot 'results\cleanup_20261101.json'
$plan = Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
if ($plan.workspace -ne $workspaceRoot) { throw 'Cleanup plan belongs to another workspace.' }
foreach ($entry in $plan.items) {
    if (-not (Test-Path -LiteralPath $entry.path)) { continue }
    $target = (Resolve-Path -LiteralPath $entry.path).Path
    if (-not $target.StartsWith($workspaceRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Target outside workspace: $target"
    }
    $item = Get-Item -LiteralPath $target -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse target: $target" }
    if ($entry.directory) {
        if ($entry.relative_path -ne 'data/upstream_nvd' -and $entry.relative_path -ne '.pytest_cache' -and $item.Name -ne '__pycache__') {
            throw "Unexpected directory: $target"
        }
        $link = Get-ChildItem -LiteralPath $target -Recurse -Force |
            Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint } | Select-Object -First 1
        if ($link) { throw "Reparse child in target: $target" }
    } elseif (-not $entry.relative_path.StartsWith('results/')) {
        throw "Unexpected file: $target"
    }
}
foreach ($entry in $plan.items) {
    if ((Test-Path -LiteralPath $entry.path) -and $PSCmdlet.ShouldProcess($entry.path, $entry.reason)) {
        Remove-Item -LiteralPath $entry.path -Recurse -Force
    }
}
if (-not $WhatIfPreference) {
    $plan.status = 'complete'
    $plan | Add-Member -NotePropertyName completed_at -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
    [IO.File]::WriteAllText($planPath, ($plan | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    Write-Output ('Cleanup complete: {0:N2} MB' -f ($plan.total_bytes / 1000000))
}
