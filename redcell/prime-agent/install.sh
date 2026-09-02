#!/usr/bin/env bash
# RedCell 를 prime-agent 설정 디렉터리에 설치한다.
#
# 사용법:
#   ./prime-agent/install.sh [TARGET_PROJECT_DIR]
# 인자가 없으면 현재 디렉터리를 대상 프로젝트로 본다.
# prime-agent 는 <project>/.prime/agent/ 아래에서 확장/스킬을 자동 발견한다.
set -euo pipefail

REDCELL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-$PWD}"
DEST="$TARGET/.prime/agent"

echo "RedCell 설치: $REDCELL_DIR -> $DEST"
mkdir -p "$DEST/extensions" "$DEST/skills" "$DEST/redcell"

# 확장/스킬을 심볼릭 링크(개발 중 수정이 바로 반영되도록).
ln -sfn "$REDCELL_DIR/prime-agent"          "$DEST/extensions/redcell"
ln -sfn "$REDCELL_DIR/skills/pentest-lab"   "$DEST/skills/pentest-lab"

# 인가 파일: 없으면 예제를 복사(사용자가 직접 채워야 함).
if [ ! -f "$DEST/redcell/authorization.yaml" ]; then
  cp "$REDCELL_DIR/config/authorization.example.yaml" "$DEST/redcell/authorization.yaml"
  echo "⚠️  $DEST/redcell/authorization.yaml 생성됨 — 반드시 본인이 권한을 가진 대상으로 수정하세요."
fi

cat <<EOF

설치 완료. 다음을 $TARGET/.prime/agent/settings.json 에 병합하세요:
$(cat "$REDCELL_DIR/prime-agent/settings.snippet.json")

그런 다음 prime-agent 를 실행하고 /scope 로 인가 상태를 확인하세요.
EOF
