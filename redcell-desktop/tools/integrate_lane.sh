#!/usr/bin/env bash
# 레인 통합 스크립트 — 워크트리의 변경을 메인 작업 트리에 적용하고 검증한다.
#
# 사용법:  bash tools/integrate_lane.sh <lane-num> [dry]
#   lane-num : 1 | 2 | 3 (각각의 워크트리 경로와 대응)
#   dry       : 실제 적용 없이 diff 통계만 출력
#
# 각 레인은 격리된 워크트리(/tmp/rc-laneN/redcell-desktop)에서 작업했다.
# 워크트리 HEAD 는 메인 작업 트리의 스냅샷 커밋이므로,
# `git diff` (HEAD 기준) + 미추적 파일로 변경분이 전부 나온다.
set -uo pipefail

LANE="${1:?lane 번호 필요 (1|2|3)}"
MODE="${2:-apply}"
MAIN="/opt/workspace/local/bsh/workspace/absolute-agent/redcell-desktop"
WT="/tmp/rc-lane${LANE}/redcell-desktop"

[ -d "$WT" ] || { echo "워크트리 없음: $WT"; exit 1; }

echo "=== 레인 ${LANE} 변경분 목록 ==="
( cd "$WT" && git status --porcelain )

PATCH="/tmp/rc-lanes/lane${LANE}.patch"
( cd "$WT" && git diff --binary HEAD ) > "$PATCH"
# 미추적 파일은 별도 목록으로 (내용까지 복사)
UNTRACKED=$( cd "$WT" && git ls-files --others --exclude-standard )

echo
echo "=== diff 통계 ==="
( cd "$WT" && git diff --stat HEAD )

if [ "$MODE" = "dry" ]; then
  echo
  echo "(dry) 미추적 파일:"
  echo "$UNTRACKED" | sed 's/^/  /'
  exit 0
fi

if [ -s "$PATCH" ]; then
  echo
  echo "=== 적용: git apply -3 (3-way) ==="
  # 1순위: 평문 apply (워크트리 HEAD == 현재 작업 트리 스냅샷이라 충돌 없음)
  # 2순위: 3-way apply (인덱스가 다를 때)
  if ( cd "$MAIN" && git apply --verbose "$PATCH" ); then
    echo "적용 성공 (plain)"
  elif ( cd "$MAIN" && git apply -3 --verbose "$PATCH" ); then
    echo "적용 성공 (3-way)"
  else
    echo "적용 실패 — 충돌. $MAIN 에서 수동 병합 필요"
    exit 2
  fi
else
  echo "(tracked 변경 없음)"
fi

if [ -n "$UNTRACKED" ]; then
  echo
  echo "=== 미추적 파일 복사 ==="
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    mkdir -p "$MAIN/$(dirname "$f")"
    cp "$WT/$f" "$MAIN/$f"
    echo "  + $f"
  done <<< "$UNTRACKED"
fi

echo
echo "=== 검증 ==="
( cd "$MAIN/src-tauri" && cargo test --offline 2>&1 | grep -E "^test result|FAILED|^error" ) || true
( cd "$MAIN" && node --check ui/app.js && echo "ui/app.js syntax OK" )
( cd "$MAIN" && node --test ui/tests/grade.test.mjs 2>&1 | grep -E "^ℹ (pass|fail)" ) || true
