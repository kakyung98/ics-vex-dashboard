#!/usr/bin/env bash
# 메인 88 배치가 끝나기를 기다린 뒤, 'failed' 로 기록된 CVE 만 CSV 에서 제거하고
# 개선된 러너(자동 재시도 포함)로 재실행한다. GPU/컨테이너 경합을 피하려고
# 메인 배치 컨테이너가 사라진 뒤에만 시작한다.
set -u
ROOT="C:/Users/user/Desktop/ICS-VEX"
CSV="$ROOT/results/verify_full_summary.csv"
LIST="$ROOT/results/exploit_all88.txt"

echo "[retry-watcher] 메인 배치 완료 대기..."
while true; do
  done=$(( $(wc -l < "$CSV") - 1 ))
  running=$(docker ps --format '{{.Image}}' 2>/dev/null | grep -c genie)
  # 88건 모두 CSV 에 있고 genie 컨테이너가 없으면 메인 배치 종료로 본다
  if [ "$done" -ge 88 ] && [ "$running" -eq 0 ]; then break; fi
  sleep 120
done
echo "[retry-watcher] 메인 배치 종료 감지 (done=$done). failed 재시도 시작."

# failed 행 제거 -> 러너가 스킵하지 않고 재시도
fails=$(awk -F, '$6=="failed"{print $1}' "$CSV")
[ -z "$fails" ] && { echo "[retry-watcher] failed 없음. 종료."; exit 0; }
echo "[retry-watcher] 재시도 대상:"; echo "$fails"
grep -v ",failed$" "$CSV" > "$CSV.tmp" && mv "$CSV.tmp" "$CSV"

# openssl 류 대형 빌드를 위해 재시도 패스는 빌드 타임아웃을 넉넉히
RETRY_TRIES=3 bash "$ROOT/tools/run_verify_full_batch.sh" "$LIST"
echo "[retry-watcher] 재시도 패스 완료."
