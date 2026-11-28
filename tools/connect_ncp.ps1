& (Join-Path $PSScriptRoot 'common/connect_ncp.ps1') @args
if ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE }
