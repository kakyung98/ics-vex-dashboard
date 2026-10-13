# ICS-VEX nightly GitHub update - runs daily at 23:30.
# Commits and pushes only when there are changes. Logs to tools/nightly_push.log.
$ErrorActionPreference = "Continue"
$repo = "C:\Users\user\Desktop\ICS-VEX"
$log  = Join-Path $repo "tools\nightly_push.log"
$ghbin = "C:\Users\user\AppData\Local\Microsoft\WinGet\Packages\GitHub.cli_Microsoft.Winget.Source_8wekyb3d8bbwe\bin"
if (Test-Path $ghbin) { $env:PATH = "$env:PATH;$ghbin" }

function Log($m) { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $m" | Out-File -Append -Encoding utf8 $log }

Set-Location $repo
Log "nightly run start"

# HOLD_PUSH sentinel — while this file exists, isolate all auto-push (system build in progress).
if (Test-Path (Join-Path $repo "tools\HOLD_PUSH")) {
    Log "HOLD_PUSH present; auto-push isolated; skip"
    exit 0
}

git add -A 2>&1 | Out-Null
$changes = git status --porcelain
if ([string]::IsNullOrWhiteSpace($changes)) {
    Log "no changes; skip"
    exit 0
}

$stamp = Get-Date -Format "yyyy-MM-dd"
git -c user.name="kakyung98" -c user.email="kakyung98@users.noreply.github.com" `
    commit -m "nightly update $stamp" 2>&1 | Out-File -Append -Encoding utf8 $log
git push origin main 2>&1 | Out-File -Append -Encoding utf8 $log
if ($LASTEXITCODE -eq 0) { Log "pushed OK" } else { Log "push FAILED exit=$LASTEXITCODE" }
