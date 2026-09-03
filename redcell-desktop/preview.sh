#!/usr/bin/env bash
# RedCell UI 브라우저 프리뷰 — 정적 서버를 켜고/끄는 간단 스크립트.
#
#   ./preview.sh          # 켜기(이미 켜져 있으면 재시작)
#   ./preview.sh stop     # 끄기
#   ./preview.sh restart  # 재시작
#
# 포트는 PORT 환경변수로 바꿀 수 있음:  PORT=8080 ./preview.sh
set -euo pipefail

PORT="${PORT:-5173}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/ui" && pwd)"
PIDFILE="/tmp/redcell-preview-${PORT}.pid"

stop() {
  if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    kill "$(cat "$PIDFILE")" 2>/dev/null || true
    rm -f "$PIDFILE"
    echo "⏹  프리뷰 종료 (port $PORT)"
  else
    # PID 파일이 없어도 포트를 붙잡고 있는 프로세스가 있으면 정리
    if command -v fuser >/dev/null 2>&1; then fuser -k "${PORT}/tcp" 2>/dev/null || true; fi
    rm -f "$PIDFILE"
    echo "⏹  실행 중인 프리뷰 없음 (port $PORT)"
  fi
}

start() {
  stop >/dev/null 2>&1 || true
  cd "$DIR"
  # 툴/터미널 세션이 끝나도 살아남도록 완전히 분리해서 띄운다.
  setsid nohup python3 -m http.server "$PORT" >/tmp/redcell-preview-${PORT}.log 2>&1 &
  echo $! > "$PIDFILE"
  sleep 0.5
  echo "▶  프리뷰 실행 중"
  echo "   http://localhost:${PORT}"
  echo "   끄기:  $(dirname "${BASH_SOURCE[0]}")/preview.sh stop"
}

case "${1:-start}" in
  stop)          stop ;;
  restart|start) start ;;
  *) echo "사용법: preview.sh [start|stop|restart]"; exit 1 ;;
esac
