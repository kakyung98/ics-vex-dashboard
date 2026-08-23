#!/usr/bin/env bash
# Build the locally-repackaged (tarball) CVEs: serve the zips over HTTP so the engine
# container can wget them, then run the build stage + regenerate records.
# Run AFTER the main batch (avoids GPU/docker contention).
set -u
ROOT="C:/Users/user/Desktop/ICS-VEX"
ENGINE="${VERIFY_ENGINE_DIR:-C:/Users/user/Desktop/cve-genie}"
LOCALSRC="$ENGINE/webapp/data/localsrc"
LIST="$ROOT/results/_group2_cves.txt"
PORT=8009

[ -f "$LIST" ] || { echo "run prepare_localsrc_build.py first"; exit 1; }
echo "serving $LOCALSRC on :$PORT"
( cd "$LOCALSRC" && python -m http.server "$PORT" ) > "$ROOT/results/_localsrc_http.log" 2>&1 &
HTTP_PID=$!
trap 'kill $HTTP_PID 2>/dev/null' EXIT
sleep 2

VERIFY_BUILD_MODEL="${VERIFY_BUILD_MODEL:-qwen2.5:14b}" bash "$ROOT/tools/retry_build.sh" "$LIST"

kill $HTTP_PID 2>/dev/null
echo "=== GROUP2 DONE ==="
