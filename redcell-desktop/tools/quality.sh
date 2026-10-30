#!/usr/bin/env bash
# RedCell 품질 게이트 — 한 번에 전부 검증한다.
#
#   bash tools/quality.sh          # 전체 (Rust 테스트 + UI 단위 + 스모크 + 스크린샷)
#   bash tools/quality.sh --fast   # Rust 테스트 + UI 단위 테스트만 (스모크 제외)
#
# 판정: 모든 단계가 통과해야 exit 0. 하나라도 실패하면 exit 1.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAST="${1:-}"
FAIL=0

hr() { printf '\n\033[1m── %s ──\033[0m\n' "$1"; }
ok()  { printf '  \033[32m✔\033[0m %s\n' "$1"; }
bad() { printf '  \033[31m✘\033[0m %s\n' "$1"; FAIL=1; }

hr "1/4 Rust 테스트 (엔진·프롬프트·하네스)"
if ( cd "$ROOT/src-tauri" && cargo test --offline 2>&1 ) | tee /tmp/rc-cargo-test.log | grep -E "^test result"; then
  if grep -qE "FAILED|test result: FAILED" /tmp/rc-cargo-test.log; then bad "Rust 테스트 실패"; else ok "Rust 테스트 통과"; fi
else
  bad "cargo test 실행 실패 (/tmp/rc-cargo-test.log)"
fi

hr "2/4 Rust 빌드 (경고 증가 확인)"
BUILD_LOG=/tmp/rc-cargo-build.log
( cd "$ROOT/src-tauri" && cargo build --offline 2>&1 ) > "$BUILD_LOG"
if grep -q "^error" "$BUILD_LOG"; then
  bad "빌드 에러"
  grep -A 6 "^error" "$BUILD_LOG" | head -30
else
  ok "빌드 성공"
fi

hr "3/4 UI 단위 테스트 (등급 산정 회귀)"
if ( cd "$ROOT" && node --test ui/tests/grade.test.mjs 2>&1 ) | tee /tmp/rc-node-test.log | grep -E "^ℹ (pass|fail)"; then
  if grep -qE "^ℹ fail [1-9]" /tmp/rc-node-test.log; then bad "UI 단위 테스트 실패"; else ok "UI 단위 테스트 통과"; fi
else
  bad "node --test 실행 실패"
fi

if [ "$FAST" = "--fast" ]; then
  hr "종료 (--fast: 스모크 생략)"
  exit $FAIL
fi

hr "4/4 UI 스모크 (Playwright, mock 모드)"
if ! python3 -c "import playwright" >/dev/null 2>&1; then
  printf '  \033[33m–\033[0m Playwright 미설치 — 스모크 생략 (pip install playwright && playwright install chromium)\n'
else
  ( cd "$ROOT" && ./preview.sh start >/dev/null 2>&1 )
  sleep 2
  SMOKE=$( cd "$ROOT" && timeout 300 python3 ui/tests/smoke.py 2>&1 )
  echo "$SMOKE" | grep -E "^(PASS|FAIL)" | tail -50
  if echo "$SMOKE" | grep -qE "^FAIL"; then
    bad "스모크 테스트 실패"
  elif echo "$SMOKE" | grep -q "0 failure(s)"; then
    ok "스모크 테스트 통과"
  else
    bad "스모크 테스트 결과 판독 불가"
  fi
  printf '  \033[33m–\033[0m 결과 탭 스크린샷: python3 tools/shot.py /tmp/rc-shots\n'
fi

hr "판정"
if [ "$FAIL" = "0" ]; then
  printf '  \033[32m✔ 전체 통과\033[0m\n'
else
  printf '  \033[31m✘ 실패 항목 있음\033[0m\n'
fi
exit $FAIL
