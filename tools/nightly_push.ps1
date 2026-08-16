# ICS-VEX 나이틀리 GitHub 업데이트 — 매일 23:30 실행
# 변경사항이 있을 때만 커밋/푸시한다. 로그는 tools/nightly_push.log 에 남긴다.
$ErrorActionPreference = "Continue"
$repo = "C:\Users\user\Desktop\ICS-VEX"
$log  = Join-Path $repo "tools\nightly_push.log"
$ghbin = "C:\Users\user\AppData\Local\Microsoft\WinGet\Packages\GitHub.cli_Microsoft.Winget.Source_8wekyb3d8bbwe\bin"
if (Test-Path $ghbin) { $env:PATH = "$env:PATH;$ghbin" }

function Log($m) { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $m" | Out-File -Append -Encoding utf8 $log }

Set-Location $repo
Log "nightly run start"

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
