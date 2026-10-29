# RedCell 배포 게이트 — 파이프라인 연동 가이드

사내 웹 서비스 배포 전 보안 게이트. **판정은 결정적 스윕에만 의존**하고
LLM 추론은 판정 경로에서 제외한다 (재현성 보장).

## 1. 실행

```sh
# 기본 (절대 Zero-High, 미인증)
sweep http://svc.internal --timeout 240 --gate --sarif gate.sarif

# 권장 (인증 + 크롤 + 정책)
export REDCELL_GATE_USER=gate-tester REDCELL_GATE_PASS='…'
sweep http://svc.internal --timeout 300 --gate \
  --policy gate/policy.example.json --sarif gate.sarif \
  --crawl 30
```

종료 코드: `0` 통과 · `1` 실패(차단 발견·대상 무응답·인증 미달) · `2` 사용법 오류.

| 플래그 | 의미 |
|---|---|
| `--gate` | 판정 모드 (기본 절대 Zero-High) |
| `--policy F` | 정책 JSON (미지정 시 내장 Zero-High) |
| `--sarif F` | SARIF 2.1.0 기록 (CI 코드 스캐닝용) |
| `--login-user U --login-pass P` | 폼 로그인 (환경변수 `REDCELL_GATE_USER`/`REDCELL_GATE_PASS` 권장, 플래그 우선) |
| `--login-url U` | 로그인 폼 URL (미지정 시 DOM→`/login` 자동 탐색) |
| `--crawl N` | 동일 호스트 bounded 크롤 (최대 N페이지, GET 전용, 파괴 경로 제외) |
| `--crawl-depth D` | 크롤 깊이 (기본 3, 최대 5) |
| `--openapi URL-OR-FILE` | OpenAPI JSON·YAML取り込み (동일 호스트 URL 또는 로컬 파일, 내부 `$ref` 해석, GET 표면을 프로브에 투입) |
| `--oob-base URL` | OOB 수신기 기동 + 덫 URL 살포 (블라인드 SSRF 확정, 원격 대상의 CI 콜백 주소 지정 — 루프백 대상은 자동 기동) |
| `--oob-bind ADDR` | OOB 수신 바인드 (기본 `127.0.0.1:0`, 원격 대상이면 도달 가능한 주소) |
| `--p1-budget N` | P1 검증 예산 (기본 96, 0이면 스킵, 최대 4096 — 심각도 우선 소진) |
| `--no-browser` | 브라우저 미사용 (정적 파싱만 — 무크롬 CI·결정적 스캔용, SPA 커버리지 제한) |
| `--danger` | **게이트에서 사용 금지** — 파괴적 프로브(기본 자격·IDOR·쓰기·Stored XSS)는 별도 승인 진단에서만 |

## 2. 정책 (`--policy`)

```jsonc
{
  "fail_on": ["critical", "high"],   // 이 심각도가 1건이라도 있으면 실패
  "require_auth": true,              // 인증 스캔 필수 (로그인 실패 시 실패)
  "suppressions": [                  // 명시적 예외 — 전 필드 필수
    {
      "category": "headers",
      "target_contains": "https://svc.internal/",
      "reason": "CSP 다음 스프린트 적용 (보안팀 합의 #123)",
      "approver": "sec-lead",
      "until": "2027-06-30"          // 만료 시 자동 부활 (fail-closed)
    }
  ]
}
```

- 억제는 `category` 정확 일치 + `target` 부분 일치로 적용된다.
- 만료·빈 사유·빈 승인자·무효 날짜는 거부되거나 무시된다.
- SARIF에는 억제 내역이 `suppressions` (kind=external)으로 기록되어 감사 추적된다.
- `cvss_env` 블록으로 환경 지표(CR/IR/AR·E/RL/RC)를 지정하면 SARIF
  `security-severity`가 환경 점수로 재계산된다 (예시는 `gate/policy.example.json`).

## 3. CI 연동

### GitHub Actions (Code Scanning)

```yaml
- run: sweep http://svc.internal --gate --sarif gate.sarif --crawl 30
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: gate.sarif }
```

### GitLab CI (게이트 + 아티팩트)

```yaml
security-gate:
  script: sweep http://svc.internal --gate --sarif gate.sarif --crawl 30
  artifacts: { paths: [gate.sarif], when: always }
```

### Jenkins (Warnings NG — SARIF 지원)

`recordIssues(tools: [sarif(pattern: 'gate.sarif')])` + 빌드 실패는 exit 코드로.

## 4. 신뢰성 근거 — 정답지 벤치마크

```sh
cd redcell-desktop/gate && python3 bench_run.py [sweep 바이너리 경로]
```

- 표준 라이브러리 Python 앱에 72개 기지 취약점 내장 (XSS·Stored XSS·SQLi·
  SSTI·SSRF·블라인드 SSRF·IDOR/BOLA·CRLF·HPP·NoSQL·리다이렉트·GraphQL·JWT·
  역직렬화·쿠키·CORS·TLS·경로 노출·순회·기본 자격·쓰기·인증 후 크롤·OpenAPI·
  YAML·시간 기반 블라인드·Stored 후보·폼 크롤).
- 현재 성적: **72/72 탐지, 클린 경로 오탐 0, 연속 동일 결과** (결정적).
- 판정 로직 단위 테스트: `cargo test --offline` (게이트·CVSS·SARIF·P1·raw 전송·
  로그인·크롤·OOB·Stored·OpenAPI·CDP 회귀 포함, `src-tauri` 에서 실행).

## 5. 커버리지 한계 (정직한 선언)

- **P1 확정은 (페이지, 파라미터)별 전수 + 전역 예산** (기본 96, `--p1-budget`로
  0~4096 조정, 심각도 우선 소진) — 신호는 전수 보고, 확정은 싱크별로 검증하되
  예산 소진 시 `p1` info로 명시하고 중단. 엄격 모드는 `fail_on`에 `medium` 추가.
- **크롤은 GET·동일 호스트·파괴 경로 제외** — JS 렌더링은 헤드리스 브라우저
  설치 시에만 (미설치면 정적 파싱 + `render` info 기록, `--no-browser`로 명시적 비활성).
  `--danger` 승인 진단에서는 비로그인·비파괴 폼 제출 크롤(최대 4개, 양성 값)이 추가된다.
- **SPA는 CDP 상호작용 탐색** — 안전 모드는 링크만(최대 6상태), `--danger`에서는
  버튼·폼 제출도 탐색한다. 로그인 폼·파괴 키워드는 제외(과차단=안전 우선).
  `--login-user/--login-pass` 지정 시 브라우저에서 직접 로그인해 인증 후 SPA
  상태까지 탐색하고(세션은 스윕 전체에 적용), 무한 스크롤·지연 로딩은 바닥
  스크롤 반복(최대 5회·높이 정체 시 중단)으로 XHR·DOM을 수집한다.
  캡차·봇방어 챌린지·WAF 차단 뒤 표면은 자동 우회 없이 `blocked-surface` info로
  미검사를 명시하고 요약에 미검사 건수를 남긴다.
- **OpenAPI는 JSON·YAML + 내부 `$ref`** — 외부 `$ref`·`servers`는 무시하고
  동일 호스트 `paths`만 사용한다 (YAML 풀파서 + 서브셋 폴백, JSON 동등 커버리지).
- **OOB는 대상→수신기 도달이 필요** — 루프백 대상은 수신기를 자동 기동하므로
  별도 egress 없이 블라인드 SSRF를 확정하고, 원격 대상은 도달 가능한
  `--oob-base` 지정이 필요하다 (미지정 시 `ssrf-signal` info로 미검사 명시).
  SQLi·CMDI에는 시간 기반 폴백(SLEEP 5초, 베이스라인<2초·주입≥4.5초·델타≥3초)이
  있어 OOB 없이도 블라인드 확정이 가능하다.
  CMDI는 in-band 출력(`id`·`ver`) 확정 + P1 시간 기반 확정을 모두 수행한다.
- **Stored XSS·쓰기 검증은 `--danger`에서만 확정** — 게이트(안전 모드)에서는
  쓰기 없이 후보 폼을 `stored-xss` info(최대 5개)로 표면화하고, 확정은 별도 승인
  진단에서 수행해 결과를 게이트에 첨부한다.
- CVSS는 카테고리 대표 벡터 (정책 `cvss_env`로 환경 지표 반영 가능) — 공식으로
  계산된 점수이며 보안팀이 벡터를 조율할 출발점이다. 밴드는 카테고리 최대 확정
  심각도와 일치하고, 벡터는 입증된 영향만 기술한다 (읽기 전용 LFI=High 상한,
  Info 표면 메모는 무점수).
- LLM 심층 진단·병합 리포트는 게이트 판정에 쓰지 않는다 (조언용 별도 실행).
