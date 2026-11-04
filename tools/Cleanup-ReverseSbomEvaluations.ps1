# Retire results derived from the deleted reverse_sbom corpus.
# Preview: .\tools\Cleanup-ReverseSbomEvaluations.ps1
# Delete explicitly listed targets: add -Apply.
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Apply)
$ErrorActionPreference = 'Stop'
$cleanupRoot = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path.TrimEnd('\')
$cleanupNames = @(
    'results/cpe_match_precision.json',
    'results/cpe_match_precision_104.json',
    'results/cpe_match_precision_ai.json',
    'results/cpe_match_precision_ambig.json',
    'results/cpe_match_precision_model.json',
    'results/cpe_match_precision_recheck.json',
    'results/l0l3_delta.json',
    'results/sbom_cpe_limits.json',
    'results/encoder_contribution.json',
    'results/cpe_ai_threshold_sweep.json',
    'results/audit_cpe_match_gt.json',
    'results/audit_item3.md',
    'results/gt_problem_layers.json',
    'results/context_vex_sensitivity.json',
    'results/item3_string_full_20261101.json',
    'results/item3_string_full_20261101.log',
    'results/identity_evidence_v3_development.json',
    'results/identity_evidence_v3_development.status.json',
    'results/identity_evidence_v3_reference_audit.json',
    'results/identity_evidence_v3_reference_audit.status.json',
    'benchmark/item3/result.json',
    'evaluation/out/report.html',
    'evaluation/out/results.json',
    'evaluation/out/run.json',
    'results/item3_identification_v2_run/item3_agents_v2_full.json',
    'results/item3_identification_v2_run/pipeline_outputs.json',
    'results/item3_identification_v2_run/predictions.jsonl',
    'results/item3_identification_v2_run/REPORT.md',
    'results/item3_identification_v2_run/status.json',
    'results/item3_identification_v2_run/summary.json',
    'results/simulations/icsa-26-281-03'
)
$checked = @()
foreach ($name in $cleanupNames) {
    $path = [IO.Path]::GetFullPath((Join-Path $cleanupRoot $name))
    if (-not $path.StartsWith($cleanupRoot+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Target escapes workspace'}
    if (-not (Test-Path -LiteralPath $path)) {continue}
    $resolved = (Resolve-Path -LiteralPath $path).Path
    if (-not $resolved.Equals($path,[StringComparison]::OrdinalIgnoreCase)) {throw 'Unexpected path resolution'}
    $item = Get-Item -LiteralPath $resolved -Force
    $ancestor = $item
    while ($ancestor -and -not $ancestor.FullName.Equals($cleanupRoot,[StringComparison]::OrdinalIgnoreCase)) {
        if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw "Linked target/ancestor: $name"}
        $ancestor = if ($ancestor.PSIsContainer) {$ancestor.Parent} else {$ancestor.Directory}
    }
    $fileCount = 1; $bytes = $item.Length
    if ($item.PSIsContainer) {
        $fileCount = 0; $bytes = 0
        $pending = [Collections.Generic.Stack[string]]::new(); $pending.Push($resolved)
        while ($pending.Count) {
            foreach ($child in Get-ChildItem -LiteralPath $pending.Pop() -Force) {
                if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'Linked descendant rejected'}
                if ($child.PSIsContainer) {$pending.Push($child.FullName)}
                else {$fileCount++; $bytes += $child.Length}
            }
        }
    }
    $checked += [pscustomobject]@{RelativePath=$name;Path=$resolved;Directory=$item.PSIsContainer;Files=$fileCount;Bytes=$bytes}
}
$checked | Select-Object RelativePath,Files,@{Name='MiB';Expression={[math]::Round($_.Bytes/1MB,2)}} | Format-Table -AutoSize
Write-Output ('Targets: '+$checked.Count)
if (-not $Apply) {Write-Output 'Preview only. Use -Apply to delete these exact targets.'; return}
$deleted = @()
foreach ($entry in $checked) {
    if ($PSCmdlet.ShouldProcess($entry.Path,'Delete retired reverse_sbom evaluation result')) {
        if ($entry.Directory) {Remove-Item -LiteralPath $entry.Path -Recurse -Force}
        else {Remove-Item -LiteralPath $entry.Path -Force}
        $deleted += $entry.RelativePath
    }
}
$report = @{workspace=$cleanupRoot;deleted=$deleted;completed_at=(Get-Date -Format o);preserved='Current model training/held-out evaluation, source campaign, latest public SBOM, runtime sessions, benchmark inputs'}
$report | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $cleanupRoot 'results/reverse_sbom_evaluation_cleanup_completed.json') -Encoding utf8
Write-Output ('Deleted targets: '+$deleted.Count)
