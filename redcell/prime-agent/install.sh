#!/usr/bin/env bash
# RedCell 를 prime-agent(pi) 설정에 장착한다.
#
# 사용법:
#   ./prime-agent/install.sh [TARGET_PROJECT_DIR] [--global]
# 인자가 없으면 현재 디렉터리를 대상 프로젝트로 본다.
#
# 기본(권장): **프로젝트 로컬 전용** — <project>/.pi/agent/ 아래에만 설치한다.
#   다른 프로젝트/디렉터리에서 pi 를 쓸 때 RedCell 인가 게이트가 전혀 간섭하지 않는다.
#   (pi 는 .pi/extensions 는 자동 발견하지만 .pi/agent/extensions 는 settings.json 의
#   extensions 배열(아래 스니펫) 또는 `-e` 플래그로 명시 로드된다.)
# --global: 모든 프로젝트에서 RedCell 을 적용하려면 전역 ~/.pi/agent/extensions 에도 링크.
#   ⚠ 전역 설치는 *모든* pi 세션의 툴 호출을 인가 목록으로 검사하므로 권장하지 않는다.
set -euo pipefail

REDCELL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-$PWD}"
DEST="$TARGET/.pi/agent"
GLOBAL="${PI_AGENT_DIR:-$HOME/.pi/agent}"
GLOBAL_FLAG=0
[ "${2:-}" = "--global" ] && GLOBAL_FLAG=1

echo "RedCell 설치(프로젝트 로컬): $REDCELL_DIR -> $DEST$([ $GLOBAL_FLAG -eq 1 ] && echo " + 전역 $GLOBAL")"
mkdir -p "$DEST/extensions" "$DEST/skills" "$DEST/redcell"

# 확장/스킬을 심볼릭 링크(개발 중 수정이 바로 반영되도록).
ln -sfn "$REDCELL_DIR/prime-agent"          "$DEST/extensions/redcell"
ln -sfn "$REDCELL_DIR/skills/pentest-lab"   "$DEST/skills/pentest-lab"

# 인가 파일: 없으면 예제를 복사(사용자가 직접 채워야 함).
if [ ! -f "$DEST/redcell/authorization.yaml" ]; then
  cp "$REDCELL_DIR/config/authorization.example.yaml" "$DEST/redcell/authorization.yaml"
  echo "⚠️  $DEST/redcell/authorization.yaml 생성됨 — 본인이 권한을 가진 대상으로 수정하세요."
fi

if [ $GLOBAL_FLAG -eq 1 ]; then
  mkdir -p "$GLOBAL/extensions"
  ln -sfn "$REDCELL_DIR/prime-agent" "$GLOBAL/extensions/redcell"
  echo "⚠️  전역 설치 완료 — 이제 모든 pi 세션에 RedCell 인가 게이트가 적용됩니다."
  echo "    (다른 프로젝트에서 걸릴까 봐 싫으면: rm \"$GLOBAL/extensions/redcell\")"
fi

cat <<EOF

설치 완료(이 프로젝트에서만 활성). pi CLI 에서 확장을 명시 로드:
  pi -e "$REDCELL_DIR/prime-agent/index.ts"

또는 아래를 $TARGET/.pi/agent/settings.json 에 병합하면 자동 로드됩니다:
$(cat "$REDCELL_DIR/prime-agent/settings.snippet.json")

데스크톱 패널은 확장을 -e 로 직접 로드하므로 아무 설정 없이 게이트가 켜집니다.
/scope 로 인가 상태를 확인하세요.
EOF