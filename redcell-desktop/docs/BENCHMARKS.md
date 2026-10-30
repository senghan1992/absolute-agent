# 독립 벤치 기록

자체 정답지(`gate/bench_run.py`, 72/72)가 아닌 **외부 독립 타겟** 실측 기록.
기대 항목은 관측된 참값에서만 도출하고, 미탐은 사유와 함께 남긴다.

실행: `cd redcell-desktop/gate && python3 extbench.py [--twice] [--out DIR]`
매니페스트: `redcell-desktop/gate/manifests/*.json`

## 결과

### 2026-10-30 (sweep dev, Linux + Chromium)

- `extbench.py` httpbin-clean: **PASS** — probes=217 hits=19
  recall=5/5 review=0 fp=0 absent-viol=0.
- 2·3단계 후 재실행: httpbin-clean **PASS** — probes=220 hits=19
  recall=5/5 review=0 fp=0 absent-viol=0 (신규 프로브 추가에도 오탐 0).
- `bench_run.py`: **PASS** — 74/74 (C53·C54 POST 폼 참값 2건 추가).
- juice-demo: 인스턴스 전면 503으로 **저하 기록** (아래 참조).
  건강 시 관측값(juice3, 2026-10-30): probes=195 hits=42 —
  sqli-signal(m) 2건(`/rest/products/search/?q=` 시드),
  headers(m) 2건, paths high 0건, secret high 0건.

## 타겟별 메모

### juice-demo (OWASP Juice Shop 공개 데모)

- 승인: OWASP 공식 공개 데모 (테스트 목적), 저RPS(5)·미인증·비파괴.
- 알려진 제약: 공유 인스턴스라 상태·지연이 흔들림 (CDP XHR 변동 가능).
- 2026-10-30 00:30 이후 전면 503 (인스턴스 장애). 이 상태의 스캔은
  `대상 루트 5xx — 결과 신뢰도 저하` 경고를 남기고 참고용으로만 기록한다.
  복구 후 `extbench.py manifests/juice-demo.json` 재실행 필요.
- 2026-10-30 01:40 재확인: 여전히 전면 503 — 재벤치 보류 유지.

### httpbin-clean (httpbin.org)

- 승인: 공개 HTTP 테스트 서비스, 저RPS(8)·비파괴.
- httpbin은 의도적으로 입력을 반사하므로 반사 관찰(cors 등)은
  오탐이 아니라 의도된 동작이다. 판정은 `verdict`로 구분한다.
  jquery 2.2.4 (CVE-2020-11022)는 실제 구버전 (`verdict=signal`).

## 이 벤치가 만든 수정 (역추적)

외부 실측이 발견해 수정한 항목 (자체 정답지에서는 안 드러남):

1. SPA 폴백 경로 오탐 (high 9건) → 소프트-404 카나리 + 루트 변형 +
   폴백 합의(5경로+) 3단 제거.
2. P1 기아 (후보 29건 중 0회 시도) → 잡 단계 상한(20%·최대 45초 예약) +
   P1 잡-직후 이동 + 중단 사유 구분 (예산·기한·취소).
3. 시크릿 오탐 (minified JS 코드조각 high 4건) → 코드 문자
   (`(){};?<>,`) 포함 값 거부.
4. 무증거 경로 판정 (`/elmah.axd` 등) → High/Medium에 본문 마커 요구,
   없으면 한 단계 강등.
5. `--rps/--threads` 예절 조절, `--seed-url` 운영자 지정 투입 (최대 8개).
6. 루트 5xx 대상 불안정 경고 (`target`, 인계 자동 포함).
7. POST 전송 기반 + POST 폼 주입 + P1 POST 재검증 (M02 잔여 해소).
8. CDP XHR POST 본문 수집(postData) + JSON·urlencoded 필드 퍼징.
9. OpenAPI 경로 세그먼트 퍼징 + P1 후보 정직 집계 + SAML/OAuth 설정 감사.
10. 팀 표준도구: `--batch/--out-dir/--history-dir`, `diff`·`history`
    서브커맨드 ([OPERATE.md](OPERATE.md)).
