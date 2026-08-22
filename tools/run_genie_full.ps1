# CVE-Genie FULL run (Data Processor + Builder + Exploiter + CTF Verifier) for one CVE.
# Split routing on Ollama: BUILD roles on qwen2.5:14b (fast, proven), EXPLOIT/VERIFY roles
# on qwen2.5:32b (stronger, to clear the Exploit Critic that beat the 7B/14B before).
# Usage:  pwsh tools/run_genie_full.ps1 CVE-2022-25235
param([Parameter(Mandatory=$true)][string]$Cve)

$ErrorActionPreference = "Stop"
$genie   = "C:\Users\user\Desktop\cve-genie"
$build   = "qwen2.5:14b"
$exploit = "qwen2.5:32b"
$v1      = "http://host.docker.internal:11434/v1"
$cache   = "$genie\webapp\data\icsvex_tierA.json"
if (-not (Test-Path $cache)) { throw "cache not found: $cache" }

# format corrector alias -> keep everything local
& ollama cp $build "gpt-4o-mini" 2>$null

docker run --rm `
  --add-host host.docker.internal:host-gateway `
  -v "$genie\src\agents:/src/agents" `
  -v "$genie\webapp\data:/data" `
  -v "$genie\webapp\shared:/shared" `
  -v "//var/run/docker.sock:/var/run/docker.sock" `
  -w /src `
  -e MODEL=ollama14 `
  -e LOCAL_LLM_BASE_URL=$v1 `
  -e LOCAL_LLM_API_KEY=ollama `
  -e "LOCAL_LLM_MODELS=ollama14=$build,ollama32=$exploit" `
  -e KNOWLEDGE_MODEL=ollama14 `
  -e PREREQ_MODEL=ollama14 `
  -e REPO_MODEL=ollama14 `
  -e REPO_CRITIC_MODEL=ollama14 `
  -e EXPLOITER_MODEL=ollama32 `
  -e EXPLOIT_CRITIC_MODEL=ollama32 `
  -e CTF_VERIFIER_MODEL=ollama32 `
  -e SANITY_MODEL=ollama32 `
  -e OPENAI_BASE_URL=$v1 `
  -e OPENAI_API_BASE=$v1 `
  -e OPENAI_API_KEY=ollama `
  cve-genie:latest `
  python3 -u main.py --cve $Cve --json /data/icsvex_tierA.json --run-type build,exploit,verify
