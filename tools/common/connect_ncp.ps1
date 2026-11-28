param([string]$Kubeconfig = "$env:USERPROFILE/Downloads/hysage-kubeconfig.yaml")
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Kubeconfig)) { throw "kubeconfig file not found: $Kubeconfig" }
Write-Output 'Cloud workbench: http://127.0.0.1:18100/precision.html (keep this connection running)'
& kubectl --kubeconfig $Kubeconfig port-forward pod/test-0 18100:18100 --address 127.0.0.1
