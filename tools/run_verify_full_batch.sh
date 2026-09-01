#!/usr/bin/env bash
# Execution-verification full batch: source-available CVEs -> build -> exploit -> verify
# via the containerized engine (local Ollama). Sequential, resumable. Captures REAL
# per-CVE outcomes + evidence (build/exploit critic decisions, generated PoC, logs).
# Usage:  bash tools/run_verify_full_batch.sh results/verify_pilot_cves.txt
set -u
ROOT="C:/Users/user/Desktop/ICS-VEX"
ENGINE="${VERIFY_ENGINE_DIR:-C:/Users/user/Desktop/cve-genie}"
SHARED="$ENGINE/webapp/shared"
LIST="${1:-$ROOT/results/verify_full_cves.txt}"
LOGDIR="$ROOT/results/verify_full_logs"
OUTDIR="$ROOT/results/verify_full"
EVID="$ROOT/results/verify_evidence"
CSV="$ROOT/results/verify_full_summary.csv"
PS1="$ROOT/tools/run_verify_full.ps1"
mkdir -p "$LOGDIR" "$OUTDIR" "$EVID"
[ -f "$CSV" ] || echo "cve,build_ok,exploit_ok,verify_ok,seconds,outcome" > "$CSV"
[ -f "$LIST" ] || { echo "no CVE list: $LIST"; exit 1; }

N=$(grep -cve '^\s*$' "$LIST")
echo "full batch: $N CVEs from $LIST"

while IFS= read -r cve; do
  cve="$(echo "$cve" | tr -d '[:space:]')"
  [ -z "$cve" ] && continue
  if grep -q "^$cve," "$CSV" 2>/dev/null; then echo "skip (done): $cve"; continue; fi
  log="$LOGDIR/$cve.log"
  # 일시장애(LLM 빈응답/포맷오류/인프라 연결거부)는 진짜 빌드 실패가 아니므로 재시도한다.
  MAX_TRIES="${RETRY_TRIES:-3}"
  attempt=0; build_ok=0; exploit_ok=0; verify_ok=0; dt=0
  while :; do
    attempt=$((attempt+1))
    echo "=== $(date '+%m-%d %H:%M:%S') full-run $cve (attempt $attempt/$MAX_TRIES) ==="
    t0=$(date +%s)
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PS1" "$cve" > "$log" 2>&1
    t1=$(date +%s); dt=$((t1-t0))
    build_ok=0; exploit_ok=0; verify_ok=0
    grep -qa "Critic accepted the repo build" "$log" && build_ok=1
    { grep -qa "Critic accepted the exploit" "$log" || grep -qa "Exploit Script Created" "$log"; } && exploit_ok=1
    if grep -qaE "verifier.*'success': 'True'|CTF.*[Ss]uccess|flag captured" "$log" && ! grep -qa "Timeout expired during phase: verifier" "$log"; then verify_ok=1; fi
    [ $build_ok -eq 1 ] && break
    if [ $attempt -lt $MAX_TRIES ] && grep -qaE "Empty Response From LLM|Connection refused|Network is unreachable|list index out of range|NoneType. object is not subscriptable|Output format is not correct" "$log"; then
      echo "  transient failure — retrying ($cve)"; sleep 5; continue
    fi
    break
  done
  if [ $verify_ok -eq 1 ]; then outcome="execution-verified"
  elif [ $exploit_ok -eq 1 ]; then outcome="exploit-generated"
  elif [ $build_ok -eq 1 ]; then outcome="build-only"
  else outcome="failed"; fi

  # collect evidence (real artifacts) into the repo
  ev="$EVID/$cve"; mkdir -p "$ev"
  cp "$log" "$ev/run.log" 2>/dev/null
  if [ -d "$SHARED/$cve" ]; then
    [ -d "$SHARED/$cve/scripts" ] && cp -r "$SHARED/$cve/scripts" "$ev/" 2>/dev/null
    [ -d "$SHARED/$cve/conversations" ] && cp -r "$SHARED/$cve/conversations" "$ev/" 2>/dev/null
  fi

  python "$ROOT/tools/_verify_record.py" "$cve" "$build_ok" "$exploit_ok" "$verify_ok" "$dt" "$outcome" "$log" "$SHARED/$cve" "$OUTDIR/$cve.json"
  echo "$cve,$build_ok,$exploit_ok,$verify_ok,$dt,$outcome" >> "$CSV"
  echo "  -> build=$build_ok exploit=$exploit_ok verify=$verify_ok ${dt}s ($outcome)"
done < "$LIST"

echo "=== FULL BATCH DONE ==="
python "$ROOT/tools/_verify_record.py" --summary "$CSV" "$OUTDIR/_summary.json"
