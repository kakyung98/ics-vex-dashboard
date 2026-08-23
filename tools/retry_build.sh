#!/usr/bin/env bash
# Retry the build stage for a list of CVEs (stronger model via VERIFY_BUILD_MODEL),
# update results/verify_build_batch.csv, and regenerate per-CVE records/evidence.
# Usage:  VERIFY_BUILD_MODEL=qwen2.5:32b bash tools/retry_build.sh results/_remaining_failed.txt
set -u
ROOT="C:/Users/user/Desktop/ICS-VEX"
LIST="${1:-$ROOT/results/_remaining_failed.txt}"
LOGDIR="$ROOT/results/verify_build_logs"
CSV="$ROOT/results/verify_build_batch.csv"
PS1="$ROOT/tools/run_verify_build.ps1"
MODEL="${VERIFY_BUILD_MODEL:-qwen2.5:14b}"
mkdir -p "$LOGDIR"
echo "retry-build ($MODEL): $(grep -cve '^\s*$' "$LIST") CVEs"

while IFS= read -r cve; do
  cve="$(echo "$cve" | tr -d '[:space:]')"; [ -z "$cve" ] && continue
  log="$LOGDIR/$cve.log"
  echo "=== $(date '+%m-%d %H:%M:%S') retry-build $cve ($MODEL) ==="
  t0=$(date +%s)
  VERIFY_BUILD_MODEL="$MODEL" powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PS1" "$cve" > "$log" 2>&1
  t1=$(date +%s); dt=$((t1-t0))
  built=0; critic=0; marker="failed"
  if grep -qa "Repo Built Successfully" "$log"; then built=1; marker="repo-built"
  elif grep -qa "Repo Builder Done" "$log"; then built=1; marker="repo-builder-done"; fi
  grep -qa "Critic accepted the repo build" "$log" && critic=1
  # update CSV row (remove old, append new)
  grep -v "^$cve," "$CSV" > "$CSV.tmp" 2>/dev/null && mv "$CSV.tmp" "$CSV"
  echo "$cve,$built,$critic,$dt,\"$marker\"" >> "$CSV"
  # force record regeneration for this CVE
  rm -f "$ROOT/results/verify_full/$cve.json"
  echo "  -> built=$built critic=$critic ${dt}s ($marker)"
done < "$LIST"

echo "=== RETRY DONE; regenerating records ==="
python "$ROOT/tools/gen_build_records.py"
