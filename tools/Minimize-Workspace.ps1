# Run in a local PowerShell window. Default is preview; -Apply performs deletion.
# Does not change Codex execution policy or attempt to elevate privileges.
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Apply, [switch]$IncludeLegacyModels)
$ErrorActionPreference = 'Stop'
$taskRoot = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path.TrimEnd('\')
$taskPlan = Get-Content -LiteralPath (Join-Path $taskRoot 'results/workspace_cleanup_plan.json') -Raw | ConvertFrom-Json
if (-not $taskRoot.Equals($taskPlan.workspace, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Plan belongs to a different workspace. Rebuild/review it before use.'
}
$safeNames = @(
    'results/integrated_page.html', 'results/integrated_page_scripts.js',
    'results/candidate_web_script.js', 'results/pages_latest_scripts.js', 'results/item4_ui_scripts.js',
    'src/__pycache__', 'tests/__pycache__', 'tools/__pycache__', 'evaluation/__pycache__',
    '.pytest_cache', 'data/upstream_nvd', 'data/_debian_cve_list.txt'
)
$legacyNames = @(
    'models/product-name-encoder-v1', 'models/ics-cpe-encoder', 'models/codebert-vuln',
    'models/identification-agents-v1', 'models/poc-sllm-lora',
    'models/vex-justifier-lora', 'models/vex-justifier-lora-v1-23k'
)
$selected = @($taskPlan.items | Where-Object {$_.category -eq 'regenerable' -or $IncludeLegacyModels})
$checked = @()
# Validate every target before deleting anything; never follow links/junctions.
foreach ($entry in $selected) {
    $name = [string]$entry.relative_path
    if ($name -notin ($safeNames + $legacyNames)) { throw "Unlisted target: $name" }
    if ($name -in $legacyNames -and -not $IncludeLegacyModels) { throw 'Legacy model option required.' }
    $path = [IO.Path]::GetFullPath((Join-Path $taskRoot $name))
    if (-not $path.StartsWith($taskRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Target escapes workspace: $path"
    }
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $resolved = (Resolve-Path -LiteralPath $path).Path
    if (-not $resolved.Equals($path, [StringComparison]::OrdinalIgnoreCase)) { throw "Unexpected resolution: $name" }
    $item = Get-Item -LiteralPath $resolved -Force
    # Check all ancestors as well as the final target before any recursion.
    $ancestor = $item
    while ($ancestor -and -not $ancestor.FullName.Equals($taskRoot, [StringComparison]::OrdinalIgnoreCase)) {
        if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Linked target/ancestor: $name" }
        $ancestor = if ($ancestor.PSIsContainer) {$ancestor.Parent} else {$ancestor.Directory}
    }
    $children = @()
    if ($item.PSIsContainer) {
        # Enumerate one level at a time, rejecting links before descending.
        $pending = [Collections.Generic.Stack[string]]::new();$pending.Push($resolved)
        while ($pending.Count) {
            foreach ($child in Get-ChildItem -LiteralPath $pending.Pop() -Force) {
                if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Linked child: $($child.FullName)" }
                if ($child.PSIsContainer) {$pending.Push($child.FullName)} else {$children += $child}
            }
        }
        if ($item.Name -eq '__pycache__' -and @($children | Where-Object {$_.Extension -ne '.pyc'}).Count) {
            throw "Unexpected non-bytecode cache contents: $name"
        }
        if ($name -eq 'data/upstream_nvd' -and @($children | Where-Object {$_.Name -notmatch '^\d{4}\.json\.gz$'}).Count) {
            throw 'NVD cache contains unexpected files. Inspect before deleting.'
        }
    } else {$children = @($item)}
    if ($env:ICSVEX_AGENT_ADAPTERS) {
        $custom = [IO.Path]::GetFullPath($env:ICSVEX_AGENT_ADAPTERS).TrimEnd('\')
        if ($custom.Equals($resolved,[StringComparison]::OrdinalIgnoreCase) -or
            $custom.StartsWith($resolved+'\',[StringComparison]::OrdinalIgnoreCase)) {
            throw "Configured adapter path is a cleanup target: $name"
        }
    }
    $bytes = ($children | Measure-Object Length -Sum).Sum
    $checked += [pscustomobject]@{Path=$resolved; RelativePath=$name; Directory=$item.PSIsContainer;
        Category=$entry.category; MiB=[math]::Round($bytes/1MB,2); Files=$children.Count; Reason=$entry.reason}
}
$checked | Select-Object RelativePath,Category,MiB,Files,Reason | Format-Table -AutoSize
$total = ($checked | Measure-Object MiB -Sum).Sum
Write-Output ("Selected logical size: {0:N2} MiB. Compressed/deduplicated physical recovery may differ." -f $total)
if (-not $Apply) {
    Write-Output 'PREVIEW ONLY. Run with -Apply locally after reviewing these exact targets.'
    if (-not $IncludeLegacyModels) {Write-Output 'Optional -IncludeLegacyModels also removes older model weights; their legacy experiments need restoration/retraining.'}
    return
}
$deleted = @()
foreach ($entry in $checked) {
    if ($PSCmdlet.ShouldProcess($entry.Path, 'Delete reviewed workspace artifact')) {
        if ($entry.Directory) {Remove-Item -LiteralPath $entry.Path -Recurse -Force}
        else {Remove-Item -LiteralPath $entry.Path -Force}
        $deleted += $entry
    }
}
if (-not $WhatIfPreference) {
    $report = @{completed_at_utc=[DateTime]::UtcNow.ToString('o'); deleted=$deleted;
        legacy_models_requested=[bool]$IncludeLegacyModels; scope='reviewed allowlist only'}
    [IO.File]::WriteAllText((Join-Path $taskRoot 'results/workspace_cleanup_completed.json'),
        ($report | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
    Write-Output ("Deleted {0} targets. Active model paths, datasets, source trees and raw evidence are outside this allowlist." -f $deleted.Count)
}
