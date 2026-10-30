# RedCell 팀 표준 운영 — 스캔·이력·diff 워크플로

웹 점검은 이 도구로 통일한다. **측정 → 저장 → 비교 → 게이트**가 표준 흐름이다.

리포트(사람이 읽는 산출물)의 등급·검증 상태·CVSS 인용 규칙은
[REPORT_STANDARD.md](REPORT_STANDARD.md) 에 있다 — 판정 근거와 반례까지 적어 둔
문서라 팀원이 감사 기준으로 삼을 수 있다.

## 포지셔닝 (확정)

- RedCell sweep = **데스크톱/CI용 결정적 스캔 도구** (SaaS 아님).
- 판정은 스윕 증거에만 의존한다. LLM 추론은 판정 경로에서 제외 (재현성).
- 실행 간 비교 키는 **지문(fingerprint)** — P-ID는 실행별 순번이라 비교에 쓰지 않는다.
- SaaS형 운영 기능(멀티테넌트·스케줄러·중앙 대시보드)은 범위 밖이다.
  팀 공유는 **리포트 JSON + index.jsonl + SARIF** 파일로 한다 (Git·아티팩트 보관).

## 1. 스캔 + 저장

```sh
# 단일 대상 — 화면 요약 + 이력 저장
sweep http://svc.internal --timeout 240 --history-dir ./history

# JSON 리포트 stdout + 파일 저장 병행
sweep http://svc.internal --json --history-dir ./history > scan.json

# 배치 — 대상 파일(줄당 1개, # 주석, 최대 64개)
sweep --batch targets.txt --out-dir ./reports --history-dir ./history \
  --timeout 180 --rps 5 --threads 4

# 배치 + 게이트 — 하나라도 실패하면 종료 1 (CI용)
sweep --batch targets.txt --out-dir ./reports --gate --policy gate/policy.json
```

- `--history-dir D`: `<host>_<port>_<ts>.json` 저장 + `D/index.jsonl`에 요약 1줄 append.
- `--out-dir D`: 배치 결과물 디렉토리 (형식은 history와 동일 — index.jsonl 포함).
- `--batch`와 위치 인자(대상)는 함께 쓸 수 없다. `--sarif`는 배치와 함께 쓸 수 없다
  (개별 JSON에서 게이트 판정을 재생성할 것).

## 2. 이력 조회

```sh
sweep history --history-dir ./history
sweep history --history-dir ./history --json   # 기계 판독 (배열)
```

출력: `started_at target 발견 N건(치명/높음) 파일명`.

## 3. 실행 간 비교 (diff)

```sh
sweep diff old.json new.json
sweep diff old.json new.json --json   # ReportDiff 기계 판독
```

- 지문 **다중집합** 기준: 신규·해소·지속 + 심각도 변경.
- P-ID는 무시한다 (신·구 리포트의 순번은 다를 수 있음).
- 대상이 다르면 `(대상 상이 — 참고용)` 표기 — CI에서는 동일 대상끼리만 비교할 것.
- 지문 없는 구 리포트는 `target|category|title` 폴백 키로 매칭한다.

## 4. CI 게이트

[GATE.md](GATE.md) 참조. 표준 패턴:

```sh
sweep http://svc.internal --timeout 300 --gate \
  --policy gate/policy.json --sarif gate.sarif \
  --history-dir ./history --crawl 30
# 종료 0 통과 · 1 실패(차단·무응답·인증 미달) · 2 사용법 오류
```

## 5. 정기 점검 루틴 (권장)

1. 주간(또는 배포마다) 배치 스캔 → `--history-dir` 누적.
2. `sweep diff 전주.json 이번주.json` → 신규 High 이상은 티켓화, 해소분은 닫기.
3. `needs_validation` 항목은 담당자 인계 (차단 표면·OOB·P1 잔량).
4. 분기마다 [BENCHMARKS.md](BENCHMARKS.md) 외부 manifest 재실행 → 탐지율 저하 감시.

## 예절·안전 (필수)

- 인가된 대상만. 외부·공유 대상은 `--rps 5 --threads 4` 이하.
- `--danger`는 승인된 점검 창에서만 (기본자격·IDOR 인접·쓰기검증).
- 자격은 환경변수 (`REDCELL_GATE_USER`/`REDCELL_GATE_PASS`) — argv·히스토리 노출 금지.
- Safe 스캔도 POST 폼에 **무해 마커**(`rc7x…`)를 제출한다 (반사 확인용).
  방명록·댓글형 기능에는 마커 글이 남을 수 있으니 운영 DB가 아닌
  테스트 인스턴스에서 점검하고, 잔류분은 `rc7x` 검색으로 정리할 것.
