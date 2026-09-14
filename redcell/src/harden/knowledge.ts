/**
 * knowledge — 하드닝 규칙 베이스 + 평가.
 *
 * HARDEN_RULES: 구성 요소/포트/플래그 조합 → (위험, 공격 시나리오, 조치 권고).
 * 전부 결정적이며 방어 관점(비파괴) 서술이다. 공격 문장은 "권고할 이유"를 보여주는 용도다.
 *
 * live 크로스체크(assault 읽기 전용 툴)의 발견에 대한 조치 권고는 FIX_INDEX 로
 * 취약점 유형별 맵핑한다(리포트 "권고" 섹션).
 */
import { hasComponent, hasFlag, portHeld } from "./profile.js";
import type { HardeningFinding, SystemProfile } from "./types.js";
import type { EngagementFinding } from "../core/types.js";

/** 한 개의 하드닝 규칙. when(프로필) 이 참이면 risk/attack/fix 권고가 발견이 된다. */
export interface HardenRule {
  id: string;
  severity: HardeningFinding["severity"];
  when: (p: SystemProfile) => boolean;
  component?: string;
  risk: string;
  attack: string;
  fix: string;
  detail?: string;
  cwe?: string;
  effort?: HardeningFinding["effort"];
}

/**
 * 규칙 베이스. 순서 = 출력 순서(비중이 큰 것부터).
 * 조건은 "구성 요소 존재(+포트/플래그 조합)"이며, "보안 통제 확인"을 권고하는 방향이다.
 */
export const HARDEN_RULES: HardenRule[] = [
  {
    id: "H-01",
    severity: "critical",
    component: "redis",
    when: (prof) => hasComponent(prof, "redis") && portHeld(prof, 6379),
    risk: "Redis 노출 — 인증 없이 명령 수신 시 가능",
    attack:
      "공격자가 6379 로 연결해 INFO, CONFIG, SLAVEOF 로 모듈 로딩/설정 조작 → 임의 파일 작성으로 RCE. 데이터 덤프도 가능.",
    fix: "requirepass 설정, protected-mode yes 유지, bind 로 내부 인터페이스 제한. 인터넷에 Redis 를 열지 말 것.",
    cwe: "CWE-306",
    effort: "low",
  },
  {
    id: "H-02",
    severity: "high",
    component: "mongodb",
    when: (prof) => hasComponent(prof, "mongodb") && portHeld(prof, 27017),
    risk: "MongoDB 노출 — 인증 없이 전체 DB 덤프 가능",
    attack: "27017 에 인증 없으면 db.list / find 로 전체 데이터(개인정보 포함) 열람·외부 전송.",
    fix: "authMode 를 require 로, 계정 최소화, 방화벽으로 내부 네트워크 제한.",
    cwe: "CWE-306",
    effort: "low",
  },
  {
    id: "H-03",
    severity: "high",
    component: "elasticsearch",
    when: (prof) => hasComponent(prof, "elasticsearch") && portHeld(prof, 9200),
    risk: "Elasticsearch 노출 — 인덱스 전체 열람·변경",
    attack: "9200 API 로 문서 검색·삭제. _reindex/_update 로 데이터 변조.",
    fix: "X-Pack security 플러그인(TLS+RBAC) 활성화, 방화벽으로 접근 주체 제한.",
    cwe: "CWE-306",
    effort: "low",
  },
  {
    id: "H-04",
    severity: "critical",
    component: "docker",
    when: (prof) => hasComponent(prof, "docker") && portHeld(prof, 2375),
    risk: "Docker API(2375) 노출 — 인증 없이 컨테이너 운영 = 호스트 루트",
    attack: "2375 는 기본적으로 인증이 없다. 노출되면 /containers/create 로 privileged 컨테이너를 만들고 /proc, 디스크 마운트로 호스트 탈출(RCE).",
    fix: "2375 를 절대 인터넷에 열지 말 것. 필요하다면 TLS mutual auth + 방화벽 주체 제한. 호스트는 UNIX 소켓만.",
    cwe: "CWE-306",
    effort: "low",
  },
  {
    id: "H-05",
    severity: "high",
    component: "kubernetes",
    when: (prof) => hasComponent(prof, "kubernetes") && portHeld(prof, 6443),
    risk: "K8s API 서버(6443) 노출 — RBAC 불확실",
    attack: "6443 접속 시 서비스 계정 토큰/서비스 키로 pod exec, secret 열람 → 클러스터 전체 제어.",
    fix: "6443 은 노드 LB/ 내부망으로만. Ingress TLS + RBAC 최소 권한 + NetworkPolicy 기본 거부. 토큰 순환.",
    cwe: "CWE-306",
    effort: "medium",
  },
  {
    id: "H-06",
    severity: "high",
    component: "etcd",
    when: (prof) => hasComponent(prof, "etcd") && portHeld(prof, 2379),
    risk: "etcd(2379) 노출 — 클러스터 상태(자격증명 포함) 열람",
    attack: "etcd 는 K8s 상태 저장소. 노출되면 secret(key/token), 서비스 계정 자격증명을 전체 덤프.",
    fix: "control-plane 네트워크로만 2379/2380. --client-cert-auth(상호 TLS) 활성화.",
    cwe: "CWE-306",
    effort: "low",
  },
  {
    id: "H-07",
    severity: "high",
    component: "rabbitmq",
    when: (prof) => hasComponent(prof, "rabbitmq"),
    risk: "RabbitMQ — 기본 계정(guest) 미변경 시 전체 큐 제어",
    attack: "guest/guest 로 AMQP(5672)/관리자(15672) 접속 → 전체 메시지 읽기/게이트웨이 발신, 인증 우회 스푸핑.",
    fix: "guest 계정 제거, TLS, 관리자 콘솔은 내부망 + SSO, ACL 로 큐별 권한.",
    cwe: "CWE-798",
    effort: "low",
  },
  {
    id: "H-08",
    severity: "high",
    component: "mqtt",
    when: (prof) => hasComponent(prof, "mqtt"),
    risk: "MQTT 브roker — 인증/TLS 불확실, 모바일 앱 직결 시 임의 발신 가능",
    attack:
      "브로커가 인증 없이 열리면 공격자는 앱 대신 topic 발신(조작 데이터/명령). 8883 TLS 없으면 중간자(MITM)로 자격증명 탈취.",
    fix: "TLS(8883)+자격증명 강제, ACL 로 장치별 권한, 앱은 cert pinning. 인증 없는 브로커를 인터넷에 열지 말 것.",
    cwe: "CWE-306",
    effort: "medium",
  },
  {
    id: "H-09",
    severity: "high",
    component: "ldap",
    when: (prof) => hasComponent(prof, "ldap") && !hasFlag(prof, "http-only"),
    risk: "LDAP(389) TLS 없음 시 자격증명 스니핑",
    attack: "비암호 LDAP bind 는 패스워드를 평문으로. sniff → 계정 탈취, LDAP 주입/디렉터리 열람.",
    fix: "LDAPS(636) 또는 STARTTLS, TLS 1.2+. 평문 389 는 내부망만 허용.",
    cwe: "CWE-319",
    effort: "low",
  },
  {
    id: "H-10",
    severity: "medium",
    component: "smtp",
    when: (prof) => hasComponent(prof, "smtp") && portHeld(prof, 25),
    risk: "SMTP(25) 오픈 리elay 가능성",
    attack: "오픈 relay 로 공격자가 이 도메인에서 스팸/피싱 발신. 자격증명 노출 리스크도 동승.",
    fix: "relay 비인증을 차단(allowlist), 587 STARTTLS, SPF/DKIM/DMARC 설정.",
    cwe: "CWE-200",
    effort: "low",
  },
  {
    id: "H-11",
    severity: "medium",
    component: "ssh",
    when: (prof) => hasComponent(prof, "ssh") && portHeld(prof, 22) && hasFlag(prof, "exposed"),
    risk: "SSH(22) 인터넷 노출 — 무한된 폭력 시도",
    attack: "24 시간 브루트포스: 공통 딕셔너리로 관리자 계정 침투 → 피벗.",
    fix: "키퀴 인증만, root login 비활성, fail2ban/레이트리밋, 가능하면 VPN/SSO 경유.",
    cwe: "CWE-307",
    effort: "low",
  },
  {
    id: "H-12",
    severity: "high",
    component: "gitlab",
    when: (prof) => hasComponent(prof, "gitlab"),
    risk: "GitLab — 최신 패치 여부·계정 정책 확인 필요",
    attack:
      "과거 GitLab CVE(파일 업로드 RCE, 시크릿 노출, 계정 탈취)가 패치 전이면 그대로 취약. 자체 가입 허용이면 공격 계정으로 레포지토리 열람.",
    fix: "최신 보안 패치 확인, self-registration 비활성, SSO/LDAP 강제, GitLab CI runner 자격증명 회전.",
    cwe: "CWE-110",
    effort: "medium",
  },
  {
    id: "H-13",
    severity: "medium",
    component: "gitlab",
    when: (prof) => hasComponent(prof, "gitlab") && hasComponent(prof, "ldap"),
    risk: "GitLab+LDAP — 인증 우회/디렉터리 열람 경로",
    attack: "LDAP 주입으로 인증 우회, GitLab 의 디렉터리 sync 를 악용해 계정 열람/승격.",
    fix: "LDAP 쿼리 파라미터화, GitLab 의 LDAP filter 제한, 주기 sync 로 계정 정지.",
    effort: "medium",
  },
  {
    id: "H-14",
    severity: "high",
    component: "jenkins",
    when: (prof) => hasComponent(prof, "jenkins"),
    risk: "Jenkins — 익명 읽기/스크립트 콘솔 노출 시 RCE",
    attack: "익명 읽기 허용이면 빌드 로그(시크릿 포함) 열람. 비관리자 스크립트 콘솔이면 RCE.",
    fix: "익명 접근 비활성, matrix-auth 로 RBAC, 스크립트 콘솔은 관리자만, 자격증명 저장소 회전.",
    cwe: "CWE-306",
    effort: "low",
  },
  {
    id: "H-15",
    severity: "high",
    component: "grafana",
    when: (prof) => hasComponent(prof, "grafana"),
    risk: "Grafana — 익명 대시보드/데이터소스 쿼리(SSRF) 가능성",
    attack: "익명 사용 ON 이면 대시보드의 시크릿/내부 토큰 열람. 데이터소스 API 로 내부 서비스 쿼리(SSRF), admin API 로 계정 생성.",
    fix: "auth.anonymous 비활성, TLS, 내부 대시보드는 인증 경유. 데이터소스 쿼리는 백엔드만.",
    cwe: "CWE-306",
    effort: "low",
  },
  {
    id: "H-16",
    severity: "medium",
    component: "prometheus",
    when: (prof) => hasComponent(prof, "prometheus") && portHeld(prof, 9090),
    risk: "Prometheus(9090) — 내부 토폴로지 노출",
    attack: "인덱스/표시 API 로 내부 서비스 주소, 포트, 메트릭 열람 → SSRF/피벗 리스크 증가.",
    fix: "9090 은 모니터링 망/인증 경유로만. --web.enable-admin-api 비활성.",
    cwe: "CWE-200",
    effort: "low",
  },
  {
    id: "H-17",
    severity: "high",
    component: "wordpress",
    when: (prof) => hasComponent(prof, "wordpress"),
    risk: "WordPress — 플러그인/콘솔 RCE, xmlrpc 취약점",
    attack: "낡은 플러그인의 파일 업로드/SQL 주입 CVE, xmlrpc.php 의 brute-force 증폭, 사용자 열람(?author=1).",
    fix: "핵심/플러그인 최신, xmlrpc.php 차단, MFA, WAF, 자동 가입 비활성.",
    cwe: "CWE-110",
    effort: "medium",
  },
  {
    id: "H-18",
    severity: "medium",
    component: "nextcloud",
    when: (prof) => hasComponent(prof, "nextcloud"),
    risk: "Nextcloud — 미패치 버전 RCE",
    attack: "과거 Nextcloud CVE(웹쉘, deserialization)가 패치 전이면 계정 탈취→데이터 열람.",
    fix: "자동 업데이트, MFA, 앱별 권한 최소화, 외부 네트워크 차단.",
    effort: "medium",
  },
  {
    id: "H-19",
    severity: "high",
    when: (prof) => hasFlag(prof, "debug"),
    risk: "디버그 모드 활성 — 상세 오류로 정보 노출",
    attack: "스택트레이스/환경 변수/쿼리 로깅으로 내부 경로·자격증명 힌트 제공 → 후속 공격의 지름길.",
    fix: "프로덕션은 debug=false, 예외는 범용 메시지 + 로그만. 상세 스택은 내부망 로그로만.",
    cwe: "CWE-209",
    effort: "low",
  },
  {
    id: "H-20",
    severity: "critical",
    when: (prof) => hasFlag(prof, "default-creds"),
    risk: "기본 자격증명 미변경 — 즉시 계정 탈취",
    attack: "공통 디렉터리로 1 분 안에 관리자 계정 → 전체 시스템 제어.",
    fix: "모든 기본/공유 계정을 개인화 + 즉시 회전. CI 체크로 미변경 계정 배포 차단.",
    cwe: "CWE-798",
    effort: "low",
  },
  {
    id: "H-21",
    severity: "critical",
    when: (prof) => hasFlag(prof, "no-auth") && hasComponent(prof, "admin"),
    risk: "관리자 서비스 인증 없음 — 즉시 완전 제어",
    attack: "인가 없이 관리 API/콘솔 접근 → 계정 생성, 구성 변경, 데이터 열람/삭제.",
    fix: "관리자 경로는 반드시 인증+RBAC+MFA. 인가 없는 엔드포인트는 내부망/VPN 경유로 한정.",
    cwe: "CWE-306",
    effort: "low",
  },
  {
    id: "H-22",
    severity: "high",
    when: (prof) => hasFlag(prof, "http-only") || hasFlag(prof, "no-tls"),
    risk: "평문 통신 — 자격증명/데이터 스니핑",
    attack: "MITM 으로 패스워드/세션 쿠키/PII 탈취, 응답 조작(trafficking).",
    fix: "TLS 1.2+ 강제, HSTS, 평문 포트를 폐기. 내부 통신도 mTLS 권장.",
    cwe: "CWE-319",
    effort: "low",
  },
  {
    id: "H-23",
    severity: "medium",
    component: "jwt",
    when: (prof) => hasComponent(prof, "jwt"),
    risk: "JWT 검증 로직 불확실",
    attack: "alg=none / 키 혼동 / replay 로 토큰 위조 → 인증 우회. 장기 유효 기간이면 리스크 증폭.",
    fix: "alg 고정(RS256/ES256), exp+jti 로 단기간+회전, kid 검증, 재사용 차단.",
    cwe: "CWE-347",
    effort: "medium",
  },
  {
    id: "H-24",
    severity: "medium",
    component: "websocket",
    when: (prof) => hasComponent(prof, "websocket"),
    risk: "WebSocket 원본 허용 불확실 — 크로스-origin 연결",
    attack: "Origin 체크 없으면 임의 사이트에서 커넥션 → CSRF + 사용자 세션 탈취.",
    fix: "Origin allowlist, 연결당 자격증명 검증, 메시지 크기/레이트 제한.",
    cwe: "CWE-352",
    effort: "low",
  },
  {
    id: "H-25",
    severity: "medium",
    component: "graphql",
    when: (prof) => hasComponent(prof, "graphql"),
    risk: "GraphQL 인트로스페션/오버페치",
    attack: "introspection ON 이면 스키마 전체 열람 → 스키마 기반 자동 공격, 오버페치로 DoS, 필드별 권한 누락.",
    fix: "프로덕션 introspection 차단, 필드별 인증, 쿼리 깊이/레이트 제한.",
    cwe: "CWE-284",
    effort: "medium",
  },
  {
    id: "H-26",
    severity: "medium",
    when: (prof) => hasFlag(prof, "cloud"),
    risk: "클라우드 인스턴스 — 메타데이터/자격증명 노출",
    attack: "IMDS(169.254.169.254) 로 IAM 임시 자격증명 탈취(SSRF 경유), 컨테이너 환경 변수의 시크릿 열람.",
    fix: "IMDSv2 강제(토큰), IAM 최소 권한, 시크릿 매니저(Secrets Manager 등) 경유, VPC 사부 네트워크.",
    cwe: "CWE-916",
    effort: "medium",
  },
  {
    id: "H-27",
    severity: "medium",
    when: (prof) => hasFlag(prof, "container"),
    risk: "컨테이너 워크로드 — 탈출 리스크",
    attack: "privileged/sidecar 소켓 마운트/과거 CVE 로 컨테이너→호스트 탈출, sidecar 에 시크릿 재사용.",
    fix: "rootless, --read-only 파일시스템, privileged=off, host 소켓 마운트 금지, 네트워크 분할.",
    cwe: "CWE-250",
    effort: "medium",
  },
  {
    id: "H-28",
    severity: "high",
    when: (prof) => hasFlag(prof, "no-mfa") && hasComponent(prof, "admin"),
    risk: "관리자 MFA 부재 — 계정 탈취가 곧 전체 제어",
    attack: "관리자 패스워드 1 개만 탈취하면 전체 시스템(데이터, 자격증명, 구성) 제어.",
    fix: "관리자에는 MFA(보안기/TOTP) 필수, 가능하면 hardware key.",
    cwe: "CWE-308",
    effort: "low",
  },
  {
    id: "H-29",
    severity: "medium",
    when: (prof) => hasFlag(prof, "no-mfa") && !hasComponent(prof, "admin"),
    risk: "MFA 부재 — 일반 계정 탈취가 곧 서비스 침투",
    attack: "비밀번호 재사용을 전제로 계정 탈취 → 데이터/기능 접근.",
    fix: "핵심 기능에 MFA, 비밀번호 정책(길이/관리), SSO 권장.",
    cwe: "CWE-308",
    effort: "medium",
  },
  {
    id: "H-30",
    severity: "high",
    when: (prof) => hasFlag(prof, "secrets-in-code"),
    risk: "코드/리포지토리에 시크릿 보관 — 자격증명 열람",
    attack: "리포지토리(공개/사부)에서 키/토큰/자격증명 탈취 → 클라우드/DB/API 계정 탈취.",
    fix: "시크릿 매니저 경유, git history 로 스캔, 즉시 회전 + CI 블록.",
    cwe: "CWE-522",
    effort: "low",
  },
  {
    id: "H-31",
    severity: "medium",
    component: "kafka",
    when: (prof) => hasComponent(prof, "kafka") && portHeld(prof, 9092),
    risk: "Kafka(9092) — 무인증 데이터 스트림",
    attack: "무인증 broker 이면 토픽 소비로 민감 데이터 연속 유출.",
    fix: "SASL/TLS, ACL 로 토픽별 권한, 내부 클러스터만 노출.",
    cwe: "CWE-306",
    effort: "medium",
  },
  {
    id: "H-32",
    severity: "high",
    component: "minio",
    when: (prof) => hasComponent(prof, "minio"),
    risk: "MinIO — S3 API 인증/TLS 불확실",
    attack: "무인증이면 버킷 전체 열람/삭제. presigned URL 관리 부재 시 장기 유효 접근.",
    fix: "기본 계정 변경, TLS, presigned 유효기간 최소화, 버킷 정책 최소 권한.",
    cwe: "CWE-306",
    effort: "low",
  },
  {
    id: "H-33",
    severity: "medium",
    component: "consul",
    when: (prof) => hasComponent(prof, "consul") && portHeld(prof, 8500),
    risk: "Consul(8500) — 토폴로지+KV 시크릿 열람",
    attack: "무인증 consul 이면 서비스 토폴로지, KV(자격증명 저장) 전체 열람.",
    fix: "ACL+TLS, KV 에 자격증명 금지, 8500 은 내부망만.",
    cwe: "CWE-306",
    effort: "low",
  },
  {
    id: "H-34",
    severity: "medium",
    component: "vault",
    when: (prof) => hasComponent(prof, "vault"),
    risk: "Vault — 인증/TLS/토큰 유효기간 확인 필요",
    attack: "무인증/평문 Vault 이면 토큰 1 개가 곧 전체 시크릿 열람.",
    fix: "TLS 필수, 토큰 최대 유효기간+회전, PKI/ACL 로 경로별 권한.",
    cwe: "CWE-319",
    effort: "low",
  },
  {
    id: "H-35",
    severity: "medium",
    component: "haproxy",
    when: (prof) => hasComponent(prof, "haproxy"),
    risk: "HAProxy stats — 인가 없는 모니터링 접근",
    attack: "stats 페이지 열람으로 내부 서비스/트래픽 정보 노출(리스크 증폭).",
    fix: "stats 경로는 기본 계정 변경+인증+내부망.",
    effort: "low",
  },
  {
    id: "H-36",
    severity: "medium",
    component: "traefik",
    when: (prof) => hasComponent(prof, "traefik"),
    risk: "Traefik 대시보드 — 인가 없는 구성 열람",
    attack: "대시보드/entryPoint 설정 열람 → 내부 토폴로지+경로 규칙 노출.",
    fix: "대시보드를 인증+TLS, 8080 노출 금지.",
    effort: "low",
  },
  {
    id: "H-37",
    severity: "high",
    component: "admin",
    when: (prof) => hasComponent(prof, "admin"),
    risk: "관리자 패널 — 비밀번호 폭력/IDOR 가능성",
    attack: "관리자 계정 1 개 탈취가 곧 전체 제어. IDOR 로 타 계정 리소스 조작.",
    fix: "MFA, IP allowlist, step-up 인증, 리소스별 소유권 검증(IDOR 차단).",
    cwe: "CWE-306",
    effort: "medium",
  },
  {
    id: "H-38",
    severity: "medium",
    when: (prof) => prof.components.length === 0 && prof.ports.length === 0,
    risk: "상세 없음 — 공격 표면 판단 불가",
    attack: "판단 못 하므로 어떤 경로가 열려 있는지 알 수 없다(검증 공백).",
    fix: "상세(구성 요소/포트/인증)를 작성하거나, --url 로 live 크로스체크를 실행하라.",
    effort: "low",
  },
];

/**
 * 프로필 평가 — HARDEN_RULES 중 when(프로필) 이 참인 것만 HardeningFinding 으로.
 * (모듈 공개: 테스트 가능)
 */
export function assessProfile(profile: SystemProfile): HardeningFinding[] {
  const out: HardeningFinding[] = [];
  for (const rule of HARDEN_RULES) {
    if (!rule.when(profile)) continue;
    out.push({
      id: rule.id,
      severity: rule.severity,
      source: "profile",
      component: rule.component,
      risk: rule.risk,
      attack: rule.attack,
      fix: rule.fix,
      detail: rule.detail,
      cwe: rule.cwe,
      effort: rule.effort,
    });
  }
  return out;
}

/**
 * live 크로스체크(읽기 전용 툴)의 발견 → HardeningFinding(조치 권고).
 * FIX_INDEX 로 취약점 유형별 맵핑, 없으면 "assault 리포트 참고" 폴백.
 */
const FIX_INDEX: Array<{ re: RegExp; fix: string; cwe?: string }> = [
  { re: /sqli|sql injection|인젝션/i, fix: "SQL 파라미터화(PreparedStatement), DB 계정 최소화, 입력 검증", cwe: "CWE-89" },
  { re: /xss|크로스?사이트/i, fix: "출력 인코딩, CSP, HttpOnly 쿠키", cwe: "CWE-79" },
  { re: /경로|path traversal|lfi|파일 읽기/i, fix: "경로 정규화+whitelist, symlink 체크", cwe: "CWE-22" },
  { re: /ssrf|내부 (?:서비스|호스팅)/i, fix: "URL 검증(스킴/호스트 allowlist), 내부 라우트 차단", cwe: "CWE-918" },
  { re: /cors/i, fix: "Origin allowlist, Vary:Origin, preflight 인증", cwe: "CWE-942" },
  { re: /이명|clickjacking|csp|click.?jacking/i, fix: "X-Frame-Options, CSP frame-ancestors", cwe: "CWE-1023" },
  { re: /jwt/i, fix: "알고리즘 고정, exp/jti 로 단기간, kid 검증", cwe: "CWE-347" },
  { re: /쿠키|세션/i, fix: "HttpOnly+Secure+SameSite, 세션 ID entropy", cwe: "CWE-601" },
  { re: /시크릿|secret|자격증명|크리덴셜/i, fix: "시크릿 매니저 경유, 즉시 회전", cwe: "CWE-522" },
  { re: /백업|아카이브|정보 (?:노출|누출)/i, fix: "아카이브 접근 차단, 정보 오류 메시지 최소화", cwe: "CWE-200" },
  { re: /waf|방화벽/i, fix: "WAF 규칙 최신, 우회 시도 로그 모니터링", cwe: "CWE-693" },
];

export function liveFindingsToHardening(
  profile: SystemProfile,
  liveFindings: EngagementFinding[],
): HardeningFinding[] {
  const out: HardeningFinding[] = [];
  let i = 0;
  for (const f of liveFindings) {
    if (f.severity === "info") continue;
    i++;
    const title = `${f.title} ${f.detail ?? ""}`.toLowerCase();
    const hit = FIX_INDEX.find((x) => x.re.test(title));
    out.push({
      id: `LV-${String(i).padStart(2, "0")}`,
      severity: f.severity,
      source: "live",
      risk: f.title,
      attack: f.impact ?? f.detail ?? "(원문 참고)",
      fix: hit?.fix ?? "assault 리포트의 툴 결과 참고 — 구체 조치는 담당 개발자와 협의",
      detail: f.evidence,
      cwe: hit?.cwe,
      effort: "medium",
    });
  }
  return out;
}
