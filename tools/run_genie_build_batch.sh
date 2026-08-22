#!/usr/bin/env bash
# Night batch: CVE-Genie Data Processor + Builder (--run-type build) on Ollama for every
# CVE in the cache. Sequential, resumable. Build success judged by real markers, NOT
# main.py's final flag (always False for build-only: "Exploiter response not found").
set -u
ROOT="C:/Users/user/Desktop/ICS-VEX"
GENIE="C:/Users/user/Desktop/cve-genie"
CACHE="$GENIE/webapp/data/icsvex_tierA.json"
LOGDIR="$ROOT/results/genie_build_logs"
CSV="$ROOT/results/genie_build_batch.csv"
PS1="$ROOT/tools/run_genie_build.ps1"
mkdir -p "$LOGDIR"
[ -f "$CSV" ] || echo "cve,build_ok,critic_ok,seconds,marker" > "$CSV"

python -c "import json;print('\n'.join(sorted(json.load(open(r'$CACHE',encoding='utf-8')))))" | tr -d '\r' > "$LOGDIR/_cves.txt"
N=$(wc -l < "$LOGDIR/_cves.txt")
echo "batch: $N CVEs from cache"

while IFS= read -r cve; do
  cve="$(echo "$cve" | tr -d '[:space:]')"
  [ -z "$cve" ] && continue
  log="$LOGDIR/$cve.log"
  if grep -q "^$cve," "$CSV" 2>/dev/null; then echo "skip (done): $cve"; continue; fi
  echo "=== $(date '+%H:%M:%S') build $cve ==="
  t0=$(date +%s)
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PS1" "$cve" > "$log" 2>&1
  t1=$(date +%s); dt=$((t1-t0))
  built=0; critic=0; marker=""
  if grep -q "Repo Built Successfully" "$log"; then built=1; marker="repo-built"
  elif grep -q "Repo Builder Done" "$log"; then built=1; marker="repo-builder-done"; fi
  grep -q "Critic accepted the repo build" "$log" && critic=1
  if [ $built -eq 0 ]; then
    marker="$(grep -aoE 'not found in cache|Timeout|Traceback|Cost exceeds|Connection|refused' "$log" | tail -1)"
    marker="${marker:-failed}"
  fi
  echo "$cve,$built,$critic,$dt,\"$marker\"" >> "$CSV"
  echo "  -> built=$built critic=$critic ${dt}s ($marker)"
done < "$LOGDIR/_cves.txt"

echo "=== BATCH DONE ==="
python -c "import csv; r=list(csv.DictReader(open(r'$CSV',encoding='utf-8'))); print('total=%d build_ok=%d critic_ok=%d'%(len(r),sum(x['build_ok']=='1' for x in r),sum(x['critic_ok']=='1' for x in r)))"
