# Run the execution-verification engine (source collection + environment build, --run-type build)
# for one CVE, ALL roles on local Ollama.
# Usage:  pwsh tools/run_verify_build.ps1 CVE-2022-37434
# Prereq: Ollama serving qwen2.5:14b on the host (0.0.0.0:11434), Docker running, the
#         containerized engine image available, tools/collect_verify_source.py has written the cache.
# Env:    VERIFY_ENGINE_DIR (engine checkout), VERIFY_ENGINE_IMAGE (container image tag).
param([Parameter(Mandatory=$true)][string]$Cve)

$ErrorActionPreference = "Stop"
$engine = if ($env:VERIFY_ENGINE_DIR) { $env:VERIFY_ENGINE_DIR } else { "C:\Users\user\Desktop\cve-genie" }
$image  = if ($env:VERIFY_ENGINE_IMAGE) { $env:VERIFY_ENGINE_IMAGE } else { "cve-genie:latest" }
$model = "qwen2.5:14b"
$ollamaV1 = "http://host.docker.internal:11434/v1"
$cache = "$engine\webapp\data\icsvex_tierA.json"

if (-not (Test-Path $cache)) { throw "cache not found: $cache (run tools/collect_verify_source.py first)" }

# Ensure the format-corrector alias exists so NO call ever leaves for OpenAI.
& ollama cp $model "gpt-4o-mini" 2>$null

docker run --rm `
  --add-host host.docker.internal:host-gateway `
  -v "$engine\src\agents:/src/agents" `
  -v "$engine\webapp\data:/data" `
  -v "$engine\webapp\shared:/shared" `
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
  $image `
  python3 -u main.py --cve $Cve --json /data/icsvex_tierA.json --run-type build
