# Run CVE-Genie's Data Processor + Builder (paper §3.1-3.2) for one CVE, ALL roles on Ollama.
# Usage:  pwsh tools/run_genie_build.ps1 CVE-2022-37434
# Prereq: Ollama serving qwen2.5:14b on the host (0.0.0.0:11434), Docker running,
#         cve-genie:latest image built, tools/genie_data_processor.py has written the cache.
param([Parameter(Mandatory=$true)][string]$Cve)

$ErrorActionPreference = "Stop"
$genie = "C:\Users\user\Desktop\cve-genie"
$model = "qwen2.5:14b"
$ollamaV1 = "http://host.docker.internal:11434/v1"
$cache = "$genie\webapp\data\icsvex_tierA.json"

if (-not (Test-Path $cache)) { throw "cache not found: $cache (run tools/genie_data_processor.py first)" }

# Ensure the format-corrector alias exists so NO call ever leaves for OpenAI.
& ollama cp $model "gpt-4o-mini" 2>$null

docker run --rm `
  --add-host host.docker.internal:host-gateway `
  -v "$genie\src\agents:/src/agents" `
  -v "$genie\webapp\data:/data" `
  -v "$genie\webapp\shared:/shared" `
  -v "//var/run/docker.sock:/var/run/docker.sock" `
  -w /src `
  -e MODEL=ollama `
  -e LOCAL_LLM_BASE_URL=$ollamaV1 `
  -e LOCAL_LLM_API_KEY=ollama `
  -e "LOCAL_LLM_MODELS=ollama=$model" `
  -e KNOWLEDGE_MODEL=ollama `
  -e PREREQ_MODEL=ollama `
  -e REPO_MODEL=ollama `
  -e REPO_CRITIC_MODEL=ollama `
  -e OPENAI_BASE_URL=$ollamaV1 `
  -e OPENAI_API_BASE=$ollamaV1 `
  -e OPENAI_API_KEY=ollama `
  cve-genie:latest `
  python3 -u main.py --cve $Cve --json /data/icsvex_tierA.json --run-type build
