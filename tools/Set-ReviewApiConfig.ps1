# Run in your own PowerShell window. Keys are never printed or put in this file.
$ErrorActionPreference = 'Stop'
$claudeModel = Read-Host 'Claude review model ID (from your provider console)'
$geminiModel = Read-Host 'Gemini review model ID (from your provider console)'
if (-not $claudeModel -or -not $geminiModel) { throw 'Both model IDs are required.' }
$claudeSecret = Read-Host 'Anthropic API key' -AsSecureString
$geminiSecret = Read-Host 'Gemini API key' -AsSecureString
if ($claudeSecret.Length -eq 0 -or $geminiSecret.Length -eq 0) { throw 'Both API keys are required.' }
[Environment]::SetEnvironmentVariable('ANTHROPIC_API_KEY', [System.Net.NetworkCredential]::new('', $claudeSecret).Password, 'User')
[Environment]::SetEnvironmentVariable('GEMINI_API_KEY', [System.Net.NetworkCredential]::new('', $geminiSecret).Password, 'User')
[Environment]::SetEnvironmentVariable('CLAUDE_REVIEW_MODEL', $claudeModel.Trim(), 'User')
[Environment]::SetEnvironmentVariable('GEMINI_REVIEW_MODEL', $geminiModel.Trim(), 'User')
$claudeSecret.Dispose()
$geminiSecret.Dispose()
Write-Host 'Review API settings saved for the current Windows user. No API requests were sent.'
