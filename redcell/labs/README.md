# 합법 실습 환경 & 윤리 규칙

화이트해커가 "잘 뚫는 법"을 익히는 유일하게 올바른 길은 **당신이 공격할 권한을 가진 대상**에서
연습하는 것이다. RedCell 는 그런 대상만 다루도록 설계되어 있다.

## 어디서 연습하나 (전부 합법)

| 환경 | 설명 | scope 예시 |
| --- | --- | --- |
| **DVWA / Juice Shop / WebGoat** | 의도적으로 취약한 웹앱. 도커로 로컬 실행. | `127.0.0.1`, `10.13.37.0/24` |
| **Metasploitable 2/3** | 취약한 리눅스 VM. | 격리 네트워크 CIDR |
| **HackTheBox / TryHackMe** | 온라인 랩. 각 플랫폼의 VPN 대역만 scope 에. | 플랫폼 지정 대역 |
| **PortSwigger Web Security Academy** | 브라우저 기반 웹 취약점 랩. | 각 랩 인스턴스 도메인 |
| **본인 소유 서버/앱** | 당신이 관리하는 것. | 해당 호스트 |
| **인가된 pentest 계약** | 서면 허가(Rules of Engagement)가 있는 대상. | 계약서 명시 범위 |

### 로컬 실습랩 30초 구축 (DVWA)

```bash
docker run --rm -it -p 127.0.0.1:8080:80 vulnerables/web-dvwa
# authorization.yaml 의 allow 에 127.0.0.1, ports 에 8080 이 있으면 바로 대상이 된다.
```

## RedCell 가 강제하는 안전장치

1. **인가 파일 필수** — `authorization.yaml` 없으면 아무 것도 실행하지 않는다.
2. **Scope 게이트(fail-closed)** — allow 에 없으면 거부, deny 는 allow 를 이긴다.
3. **인가 기간** — `authorized_until` 이 지나면 동작 정지.
4. **파괴/DoS 차단** — `rm -rf`, `DROP TABLE`, 볼류메트릭 공격 등은 intent 판정으로 차단.
5. **RPS 제한** — 무차별 대입·과부하 방지.
6. **최소 영향 원칙** — 취약점은 PoC 최소 범위로만 증명, 데이터 전량 덤프 금지.
7. **로컬 보관** — 학습·발견은 외부로 전송하지 않는다(`learning.share_findings: false`).

## 하지 말아야 할 것

- ❌ 권한 없는 실제 서비스(회사·타인·공공 사이트)를 대상으로 설정하는 것.
- ❌ 실제 사용자 데이터 탈취/유출, 서비스 중단, 랜섬웨어류 페이로드.
- ❌ scope 밖 측면 이동, 탐지 회피를 위한 은닉(악의적 목적).

RedCell 를 권한 없는 대상에 사용하는 순간 그것은 "화이트해커"가 아니며,
대부분의 국가에서 형사 처벌 대상이다. 이 도구의 유일한 목적은 **인가된 환경에서의 학습과 방어**다.

---

# 랩 벤치마크 (P1) — 자율 해결률 메트릭

`labs/<name>/` 아래 `server.cjs`(랩 구현) + `manifest.yaml`(정답/기대) 쌍으로 랩을 정의한다.
`npm run lab-bench` 는 각 랩을 기동 → URL 하나만 assault 파이프라인에 전달 →
`report.json` 을 manifest 기대와 대조해 **해결(solved)/미해결** 을 판정하고 해결률을 출력한다.

## 해결 판정 기준
| 기대 항목(manifest.expect) | 뜻 |
| --- | --- |
| `findingText` | 제목에 포함돼야 할 취약점 클래스 문자열 (예: "SQL Injection") |
| `verified` | 클래스 근거 증거가 **검증(실증) 단계**까지 올라가야 함 |
| `proofContains` | 검증된 착취(proof)에 포함돼야 할 문자열 (예: "UNION 실증") |
| `evidenceCategory` | 증거 카테고리 (error / pii / secret / **exploit** …) |
| `clean: true` | 클린 랩: 발견 0 + 검증 증거 0 이어야 해결(오탐 FP 통제) |

- 클래스 발견 실패 = 미해결(FN)
- 발견했지만 검증 실패 = 미해결(가능성 단계)
- 발견 + 검증(착취 실증)까지 = 해결

## 실행
```bash
npm run lab-bench                          # 로컬 랩 전체(자동 기동/종료)
npx tsx bench/lab-bench.ts --skip-start --labs labs/portswigger/manifest.yaml   # 외부 랩(PortSwigger 등, 직접 대기)
npx tsx bench/lab-bench.ts --json bench-out.json
```

## 랩 목록
| 랩 | 클래스 | 정답 조건 |
| --- | --- | --- |
| `vuln-union` | SQLi | "SQL Injection" 발견 + UNION 실증(verified, error) |
| `vuln-idor` | IDOR | "IDOR" 발견 + 타인 데이터 열람 실증(verified, pii) |
| `vuln-creds` | credential-reuse-chain | 노출 자격증명 → 로그인 → 보호자원 접근 체이닝 실증(verified, endpoint) |
| `clean-shop` | none | 발견 0 + 검증 증거 0(클린, FP 통제) |
| `vuln-pyagent` | blind-command-injection | "명령 실행" 발견 + 로그 회수로 서버 파일 탈취 실증(verified, endpoint, proof `FLAG`) |
| `vuln-xss` | XSS | "Reflected XSS" 발견 + 반사 실증(verified, exploit, proof `XSS 실증:`) |
| `vuln-ssti` | SSTI | "Server-Side Template Injection" 발견 + 산술 평가 실증(verified, exploit, proof `SSTI 실증:`) |
| `vuln-ssrf` | SSRF | "SSRF" 발견 + 메타데이터 반사 실증(verified, exploit, proof `SSRF 실증:`) |
| `vuln-lfi` | LFI | "Path Traversal" 발견 + /etc/passwd 노출 실증(verified, exploit, proof `LFI 실증:`) |
| `vuln-redirect` | open-redirect | "Open Redirect" 발견 + canary 30x 실증(verified, exploit, proof `오픈 리다이렉트 실증:`) |
| `vuln-xxe` | XXE | "XML External Entity" 발견 + 엔티티 확장 실증(verified, exploit, proof `XXE 실증:`) |

P2 체이닝: evidence 스테이지에서 노출된 자격증명(`/.env` 등의 키-값)을 재사용해
로그인 폼(`<input type=password>`)을 찾고, 세션 실증(Set-Cookie → 보호자원 응답)까지
가면 verified 체인 증거(`chain-N`)로 보고서에 추가된다. 시도별 fresh cookie jar,
자격증명 원문은 증거에서 마스킹.

## PortSwigger 어댑터
인가된 WSA 랩 인스턴스(`*.web-security-academy.net`)는 `source: portswigger`,
`start: []`(기동 생략) manifest 로 동일하게 채점한다. 라이브 인스턴스 URL 과
`--skip-start` 로 실행하면 된다. 로컬 랩과 동일한 "verified 착취 → 해결" 기준이 적용된다.

> 랩 벤치마크는 인가된 대상(scope)에서만 실행한다. 외부 랩 실행 전
> `authorization.yaml` 에 대상 도메인 추가 필수.
