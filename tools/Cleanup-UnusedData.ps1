# Preview by default. -Apply deletes only the six listed legacy data files.
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Apply)
$ErrorActionPreference='Stop'
$workspaceRoot=(Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path.TrimEnd('\')
$dataRoot=[IO.Path]::GetFullPath((Join-Path $workspaceRoot 'data'))
if ((Get-Item -LiteralPath $dataRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'Linked data directory rejected'}
$names=@('cti_extractions.json','git_grep_hits.json','nvd_refs_full.json','release_diff.json','source_locations_patched.json','poc_sft.jsonl')
$checked=@()
foreach ($name in $names) {
    $path=[IO.Path]::GetFullPath((Join-Path $dataRoot $name))
    if (-not $path.StartsWith($dataRoot+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Target escapes data directory'}
    if (-not (Test-Path -LiteralPath $path)) {continue}
    if (-not (Resolve-Path -LiteralPath $path).Path.Equals($path,[StringComparison]::OrdinalIgnoreCase)) {throw 'Unexpected path resolution'}
    $item=Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Only regular files are allowed'}
    $checked+=$item
}
$checked | Select-Object Name,@{Name='KiB';Expression={[math]::Round($_.Length/1KB,2)}} | Format-Table -AutoSize
Write-Output ('Targets: '+$checked.Count)
if (-not $Apply) {Write-Output 'Preview only. Add -Apply to delete the exact listed files.';return}
$deleted=@()
foreach ($item in $checked) {
    if ($PSCmdlet.ShouldProcess($item.FullName,'Delete unused legacy data file')) {
        Remove-Item -LiteralPath $item.FullName -Force
        $deleted+=$item.Name
    }
}
Write-Output ('Deleted files: '+$deleted.Count)
