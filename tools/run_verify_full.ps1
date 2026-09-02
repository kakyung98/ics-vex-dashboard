# FULL execution-verification run (source collection + build + exploit + verify) for one CVE.
# All roles on qwen2.5:14b (9GB, fits the 16GB GPU). 32b OOM-ed here; coder:14b emits
# tool calls as markdown JSON the agent framework cannot parse. The earlier 14b exploit
# failure was a get_file schema bug (fixed in cve-genie/src/toolbox/file_ops.py).
# Usage:  pwsh tools/run_verify_full.ps1 CVE-2022-25235
# Env:    VERIFY_ENGINE_DIR (engine checkout), VERIFY_ENGINE_IMAGE (container image tag).
param([Parameter(Mandatory=$true)][string]$Cve)

$ErrorActionPreference = "Stop"
$engine  = if ($env:VERIFY_ENGINE_DIR) { $env:VERIFY_ENGINE_DIR } else { "C:\Users\user\Desktop\cve-genie" }
$image   = if ($env:VERIFY_ENGINE_IMAGE) { $env:VERIFY_ENGINE_IMAGE } else { "cve-genie:latest" }
# 16GB VRAM 제약: 32b(19GB)는 안 들어가 CPU 오프로드 실패한다.
# qwen2.5:14b(9GB) 한 모델로 통일. 32b(19GB)는 VRAM 초과로 OOM, coder:14b 는 tool-call 을
# 마크다운 JSON 으로 뱉어 RepoBuilder 파싱 실패. plain 14b 는 빌드에서 프로토콜 검증됨.
$build   = "qwen2.5:14b"
$exploit = "qwen2.5:14b"
$v1      = "http://host.docker.internal:11434/v1"
$cache   = "$engine\webapp\data\icsvex_tierA.json"
if (-not (Test-Path $cache)) { throw "cache not found: $cache" }

# format corrector alias -> keep everything local
& ollama cp $build "gpt-4o-mini" 2>$null

docker run --rm `
  --add-host host.docker.internal:host-gateway `
  -v "$engine\src\agents:/src/agents" `
  -v "$engine\src\toolbox:/src/toolbox" `
  -v "$engine\src\prompts:/src/prompts" `
  -v "$engine\src\main.py:/src/main.py" `
  -v "$engine\webapp\data:/data" `
  -v "$engine\webapp\shared:/shared" `
  -v "//var/run/docker.sock:/var/run/docker.sock" `
  -w /src `
  -e MODEL=ollama14 `
  -e TIMEOUT=2700 `
  -e EXPLOIT_TIMEOUT=3600 `
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
  $image `
  python3 -u main.py --cve $Cve --json /data/icsvex_tierA.json --run-type build,exploit,verify
