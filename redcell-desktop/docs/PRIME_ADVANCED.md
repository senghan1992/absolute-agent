# prime-agent 고도화 (RedCell 연동)

prime-agent 0.10 실측 구조: 단일 `python_repl` + REPL 내 PTC
(`bash()`·`edit.run`·`websearch.run`·`rlm.*`·harness). RedCell 은 이 구조에 맞춰
아래 9개 고도화를 적용했다 (`prime-agent prompt` + 가짜 키 프로브로 검증).

## 적용됨 (기본 on)

1. **프로세스 그룹 kill** — 위반 차단·중지·프리플라이트 초과 시 자식 트리 전체에
   SIGTERM(1.5초 내 미종료 시 SIGKILL). 고아 curl·python 자식의 탈취 완수 차단.
   (`kill_engine_child`, Unix. setsid 이탈 자손은 잔여)
2. **전담 HOME 격리 + 사후 감사** — prime 자식의 HOME 을
   `prime-sessions/<id>/<tag>/home` 으로 두고 `.prime` 만 실제 설정에 연결.
   work dir 밖 기록은 격리 후 `[sys] 주의: 작업 폴더 밖 기록 N건` 으로 1회 보고.
   (Unix. /tmp 절대경로 기록은 스킬 금지로만 커버 — 잔여)
3. **도구 안내 v2** (`PRIME_TOOLING`) — urllib + bash() 병렬 패턴
   (전부 띄우고 await), curl `-sS -m 10`·jq 규율, handle.kill() 타임아웃 규율,
   REPL 영속, edit.run 결과물 규칙, 전체 URL 리터럴 강제.
4. **구조화 핸드오프** — 워커가 텍스트와 별개로 findings JSON 을 절대경로에 저장
   (prime: `<tag>/work/findings-<id>.json`, pi: `sessions/findings-<piq>-<id>.json`).
   collector 가 결정적으로 선독해 텍스트보다 우선 병합. 파일 없으면 텍스트 폴백.
5. **결과측 탐지** — `tool_execution_end` 전문에서 인가 밖 호스트가 나오면
   `[경고]` 노트 (실행당 5종, 차단 아님). 동적 URL 우회의 사후망.
6. **단일 블록 정찰 규율** — 워커·추적·병합에만 부착. REPL 안에 세션·쿠키·변수를
   모아 fresh-kernel 상태 단절을 줄인다. 자유 채팅에는 미부착.
7. **`websearch.run`·`rlm.spawn` 금지** — 스킬 + 도구 안내에 명시 (전자는 스코프 밖
   접촉, 후자는 호출 단위 감사 회피). 코드는 캡처에 남아 사후 확인 가능.

## 실험적 (env 게이트)

8. **자율 병합** — `REDCELL_PRIME_AUTONOMOUS=1` 이면 merge 계열 실행에만
   `--autonomous --autonomous-max-turns 6 --autonomous-gate <gate.sh>` 를 붙이고,
   collector 에게 `report.md` 저장을 지시한다. 게이트는 존재 + `##` 구조 검사.
   플래그 파싱은 가짜 키 프로브로 확인, 실제 루프는 라이브 키 환경에서 검증 필요.

## 보류 (실측 후 기각)

9. **daemon 모드 커널 재사용** — 기각. 라이브 키 실측 결과 커널 부팅은
   0.9초에 불과하고 전체 실행 시간은 LLM 응답이 지배한다 (lge-aigw trivial
   프롬프트 총 2초). 데몬 상주 + 세션 재사용이 아껴주는 1초 미만 대비 구현
   복잡도·고장면이 크므로, 스폰 시차(버스트 분산) + `--offline` 조합을
   정식으로 유지한다. `--mode daemon` 단독 실행은 무응답 행 확인, ACP
   `initialize` 는 정상 응답 확인 (2026-10-28).

## 실측 확정 형상 (prime-agent 0.10 + lge-aigw)

- 터미널 이벤트는 `agent_end` (`agent_settled` 없음, `harness_digest` 없음).
- 중첩 `text_end` 없음 — `text_delta` 누적 + `message_end` 로 회수.
- `tool_execution_end` 에 `isError`·`durationMs` 없음 —
  `result.details.status`·`durationMs` 로 판정.
- 내부 `bash()` 호출은 별도 이벤트 없이 `details.bashCommands` 로만 노출.
- `bash()` 반환 핸들은 `.output` 으로 꺼낸다 (`.strip()` 없음).

## 운영 플래그

- `REDCELL_PRIME_AUTONOMOUS=1` — 자율 병합 (실험적)
- `REDCELL_PRIME_BIN` — 바이너리 경로 (기존)
- `REDCELL_ENGINES_JSON` — 핀 오버라이드 (기존)
