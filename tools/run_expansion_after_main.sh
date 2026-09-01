#!/usr/bin/env bash
# 메인 88 배치가 완전히 끝난 뒤, 확장 18건을 full 파이프라인으로 돌린다.
# 종료 판정: genie 컨테이너가 GRACE 초 동안 '연속으로' 없으면 메인 종료로 본다.
# (CVE 사이 공백은 1분 미만이므로, 5분 연속 부재면 배치가 끝난 것.)
# 프로세스 문자열 매칭을 쓰지 않아 self-match 오탐이 없다.
set -u
ROOT="C:/Users/user/Desktop/ICS-VEX"
EXP_LIST="$ROOT/results/exploit_expand.txt"
GRACE=300      # 5분 연속 부재
STEP=60

genie_up() { docker ps --format '{{.Image}}' 2>/dev/null | grep -c genie; }

echo "[expansion] 메인 배치 종료 대기 (genie 컨테이너 ${GRACE}s 연속 부재 감지)..."
absent=0
while :; do
  if [ "$(genie_up)" = "0" ]; then
    absent=$((absent+STEP))
    [ "$absent" -ge "$GRACE" ] && break
  else
    absent=0
  fi
  sleep "$STEP"
done
echo "[expansion] 메인 종료 확인 ($(date '+%m-%d %H:%M:%S')). 확장 $(grep -c . "$EXP_LIST")건 시작."

RETRY_TRIES=3 bash "$ROOT/tools/run_verify_full_batch.sh" "$EXP_LIST"
echo "[expansion] 확장 패스 완료 ($(date '+%m-%d %H:%M:%S'))."
