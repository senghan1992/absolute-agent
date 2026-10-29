# 엔진 업그레이드 런북 (pi / prime-agent)

RedCell Desktop 은 두 외부 엔진을 감싸고 있다. 두 프로젝트는 오픈소스로 계속
발전하므로, 새 릴리스가 나오면 아래 절차로 추종한다. 버전의 단일 출처는
`redcell-desktop/engines.json` 이다.

## 1. 버전 올리기 (필수)

1. `engines.json` 의 `pi.pinned` / `prime_agent.pinned` 을 새 버전으로 올린다.
   `min` 은 그 버전의 기능이 반드시 필요할 때만 함께 올린다.
   (`known_good` 에는 CI 로 검증된 버전을 추가한다.)
2. Rust 백엔드는 핀을 자동 반영한다 (`detect_engines` 버전 표시,
   `ensure_pinned_pi` managed 설치, `warn_stale_prime` 경고).
3. README 의 버전 표기(`동작 원리` 절)를 새 버전과 일치시킨다.

환경변수 `REDCELL_ENGINES_JSON` 으로 핀 파일 경로를 오버라이드할 수 있다
(테스트·사내 미러용).

## 2. 호환성 점검 (릴리스마다)

- [ ] `detect_engines` 로컬 확인: pi `node <cli> --version`,
      prime-agent `--version` 이 새 버전으로 잡히는지.
- [ ] 플래그 스냅샷: `pi --help` 에 `-e/--mode/--session-id/-p/--provider/--model/--api-key`,
      `prime-agent --help` 에 `--mode/--print/--skill/--session-dir/--continue/--provider/--model/--api-key`
      가 그대로 있는지 diff.
- [ ] `cargo test` 전체 통과 (프로토콜 verbatim 픽스처 포함).
- [ ] prime-agent 계약 테스트 (가짜 키 실행):
      `--mode json --print` 스트림에 `session/message_end/agent_end` 가 오고,
      ` prime_session_has_history` 가정(세션 저장 여부)·`--api-key` 반영 여부를
      재확인한다. 깨지면 `prime_carry_context`·`classify_ping_failure` 를 갱신한다.
- [ ] pi 확장 훅 계약: `tool_call {toolName, input}` 형상과
      `before_agent_start` 반환 교체가 유효한지 `redcell/prime-agent` 테스트로 확인.
- [ ] 새 이벤트 무시 경고: 진단 1회 실행 후 `[sys] 참고: 엔진이 보낸 새 형식 이벤트`
      노트가 뜨면 `pump_pi_stdio` 의 무시 목록·파서를 갱신한다.

## 3. 자동화

- CI `engine-compat` 잡 (`.github/workflows/engine-compat.yml`):
  `known_good × {linux, windows}` 매트릭스로 설치→플래그 스냅샷→`cargo test` 를
  돌린다. weekly 스케줄이 npm latest 를 조회해 핀 갱신 이슈를 만든다.
- 앱 내 조기 감지: 미지 JSON 이벤트 종류는 무시 즉시 계수되어 실행 노트로
  1회 보고된다. 새 pi/prime-agent 릴리스 직후 첫 진단에서 바로 드러난다.
- UI 경고: 설치 버전이 `min` 보다 낮으면 설정·온보딩 화면에
  `구버전 X (최소 Y) — 업데이트 권장` 배지가 뜬다.

## 4. 실측 깨짐 기록 (회귀 방지)

- prime-agent 0.10: `--session-dir` 무저장·`--continue` 새 세션 발급 →
  `prime_carry_context` 프롬프트 캐리로 우회. 고쳐지면 우회를 걷어낸다.
- prime-agent 0.10: `--api-key` 무시 → models.json 동기화 + env 주입 병기 +
  `classify_ping_failure` 안내. 고쳐지면 안내를 걷어낸다.
- prime-agent 첫 실행 시 python kernel 셋업(~30s) → preflight 타임아웃 여유 유지.
