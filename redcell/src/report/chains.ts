/**
 * chains — 개별 발견을 "공격 체인"으로 엮는다.
 *
 * 낱개 취약점보다 조합이 더 위험하다(예: SSRF+메타데이터 = 클라우드 크리덴셜 탈취,
 * XSS+오픈리다이렉트 = 세션 탈취 피싱). 방어측이 "어떤 조합을 먼저 끊어야 하는지"
 * 우선순위를 잡도록, 발견들의 조합을 탐지해 상위 위험 체인으로 제시한다.
 */

import type { EngagementFinding } from "../core/types.js";

export interface AttackChain {
  title: string;
  severity: EngagementFinding["severity"];
  links: string[]; // 엮인 발견 제목들
  impact: string;
  defense: string;
}

interface Rule {
  needs: RegExp[];
  make: (matched: EngagementFinding[]) => Omit<AttackChain, "links">;
}

const RULES: Rule[] = [
  {
    needs: [/ssrf/i, /(metadata|메타데이터|클라우드)/i],
    make: () => ({
      title: "SSRF → 클라우드 크리덴셜 탈취",
      severity: "critical",
      impact: "SSRF 로 인스턴스 메타데이터에 접근해 임시 자격증명을 탈취 → 클라우드 계정 측면이동.",
      defense: "메타데이터 접근 차단(IMDSv2 강제), egress 허용목록, URL 검증/차단.",
    }),
  },
  {
    needs: [/xss/i, /open redirect|오픈 리다이렉트/i],
    make: () => ({
      title: "XSS + 오픈 리다이렉트 → 세션 탈취 피싱",
      severity: "high",
      impact: "신뢰 도메인에서 외부로 유도 + 스크립트 실행 조합으로 세션/자격증명 탈취 피싱 신뢰도 상승.",
      defense: "출력 인코딩+CSP, 리다이렉트 목적지 허용목록, 쿠키 HttpOnly/SameSite.",
    }),
  },
  {
    needs: [/cors/i, /(idor|접근통제|broken object)/i],
    make: () => ({
      title: "CORS 오설정 + IDOR → 교차출처 데이터 탈취",
      severity: "high",
      impact: "느슨한 CORS+credentials 로 피해자 브라우저에서 타 사용자 객체(IDOR)를 교차출처로 읽어냄.",
      defense: "CORS 오리진 엄격 검증(와일드카드+credentials 금지), 객체 수준 인가.",
    }),
  },
  {
    // 첫 조건은 "실제 자격증명/시크릿 노출"이어야 한다. 단순히 제목에 '노출'이
    // 들어간 발견(예: "API 명세 노출")만으로는 자격증명 재사용 체인을 세우지 않는다.
    needs: [/(\.env|secret|시크릿|크리덴셜|자격증명|api[_-]?key|access[_-]?token|토큰|password|비밀번호)/i, /(idor|api|jwt|인증|auth)/i],
    make: () => ({
      title: "노출 자격증명 재사용 → 인증된 표면 침투",
      severity: "high",
      impact: "노출된 키/토큰으로 인증 표면에 접근(발견 체이닝) → 권한 있는 데이터/기능 접근.",
      defense: "노출 파일 제거, 자격증명 즉시 폐기·회전, 비밀은 서버측 보관/최소권한.",
    }),
  },
  {
    needs: [/(lfi|path traversal|경로 조작)/i, /(업로드|upload)/i],
    make: () => ({
      title: "파일 업로드 + LFI → 원격코드실행(RCE) 가능성",
      severity: "high",
      impact: "업로드한 파일을 LFI 로 포함/실행하는 고전 RCE 경로(로그 포이즈닝 포함).",
      defense: "업로드 저장소 실행 불가·격리, 확장자/MIME 서버검증, 파일 포함 경로 차단.",
    }),
  },
  {
    // RCE 계열(SSTI·커맨드 인젝션·역직렬화) + SSRF → 코드실행 발판으로 내부망 장악.
    needs: [/(ssti|template injection|템플릿 인젝션|command injection|커맨드 인젝션|rce|원격코드|역직렬화|deserial)/i, /ssrf/i],
    make: () => ({
      title: "RCE(코드실행) + SSRF → 내부망 측면이동·장악",
      severity: "critical",
      impact: "코드실행 발판에서 SSRF 로 내부 서비스/메타데이터에 접근 → 크리덴셜 탈취·내부망 피벗으로 인프라 장악.",
      defense: "입력의 코드/템플릿 평가 차단·역직렬화 금지, egress 허용목록, 내부 서비스 인증.",
    }),
  },
  {
    // SQLi + 인증/세션 계열 → 인증 우회 + 자격증명 DB 탈취.
    needs: [/(sql injection|sqli|sql 인젝션)/i, /(login|로그인|auth|인증|jwt|세션|session|자격증명|credential|password|비밀번호)/i],
    make: () => ({
      title: "SQL 인젝션 → 인증 우회 + 자격증명 DB 탈취",
      severity: "critical",
      impact: "SQLi 로 인증 쿼리를 우회하거나 사용자/해시 테이블을 통째로 덤프 → 전 계정 탈취·권한 상승.",
      defense: "파라미터 바인딩(Prepared Statement)·ORM, 최소 권한 DB 계정, 저장 크리덴셜 해시·솔팅.",
    }),
  },
  {
    // XXE + SSRF → 내부 파일/포트 접근(엔티티 기반 내부 요청).
    needs: [/(xxe|xml external|외부 엔티티)/i, /(ssrf|내부|internal|메타데이터|metadata)/i],
    make: () => ({
      title: "XXE → 내부 파일 열람·SSRF",
      severity: "high",
      impact: "XML 외부/내부 엔티티로 서버 파일 열람 및 내부 서비스로의 요청(SSRF) → 설정·크리덴셜 노출.",
      defense: "XML 파서 외부 엔티티/DTD 비활성화, 스키마 검증, 내부 egress 차단.",
    }),
  },
  {
    // 오픈 리다이렉트 + 토큰/OAuth → 인가 코드/토큰 탈취.
    needs: [/(open redirect|오픈 리다이렉트)/i, /(oauth|jwt|token|토큰|sso|인가 코드|authorization code)/i],
    make: () => ({
      title: "오픈 리다이렉트 → OAuth/토큰 탈취",
      severity: "high",
      impact: "신뢰 도메인의 리다이렉트로 OAuth redirect_uri/토큰을 공격자 도메인으로 유출 → 계정 연동 탈취.",
      defense: "리다이렉트 목적지 허용목록, OAuth redirect_uri 정확 매칭, state/nonce 검증.",
    }),
  },
  {
    // Host 헤더 주입 + 캐시 포이즈닝 → 오염 응답의 캐시 확산.
    needs: [/(host header|host 헤더|호스트 헤더)/i, /(cache|캐시)/i],
    make: () => ({
      title: "Host 헤더 주입 + 캐시 포이즈닝 → 대규모 확산",
      severity: "high",
      impact: "스푸핑 Host 가 반영된 응답이 캐시를 통해 다수 사용자에게 서빙 → 리다이렉트/XSS/컨텐츠 위변조 확산.",
      defense: "캐시 키에 관련 헤더 포함 또는 unkeyed 입력 반영 제거, 절대 URL 은 신뢰 설정값으로 생성.",
    }),
  },
  {
    // 약한 세션/세션 노출 + IDOR → 계정 탈취 자동화.
    needs: [/(약한 세션|weak session|session id|세션 id|세션의 url|session-in-url|픽세이션|fixation)/i, /(idor|접근통제|broken object)/i],
    make: () => ({
      title: "세션 취약 + IDOR → 계정 탈취·대량 데이터 수집",
      severity: "high",
      impact: "예측/노출된 세션으로 임의 사용자 컨텍스트를 확보하고 IDOR 로 타 사용자 객체를 열람·조작 → 대량 계정 탈취.",
      defense: "고엔트로피 세션·로그인 시 재발급·HttpOnly 전용, 객체 수준 인가(소유권 검증).",
    }),
  },
];

/** 발견 집합에서 성립하는 공격 체인을 도출한다. */
export function deriveChains(findings: EngagementFinding[]): AttackChain[] {
  const text = (f: EngagementFinding) => `${f.title} ${f.detail} ${f.evidence ?? ""}`;
  const chains: AttackChain[] = [];
  for (const rule of RULES) {
    // 각 조건을 만족하는 발견을 찾는다. 한 발견이 여러 조건을 겸할 수 있다
    // (예: "SSRF → 메타데이터 접근"은 한 발견이 ssrf+metadata 를 모두 충족).
    const matched = new Set<EngagementFinding>();
    const allNeedsMet = rule.needs.every((need) => {
      const hit = findings.find((f) => need.test(text(f)));
      if (hit) matched.add(hit);
      return !!hit;
    });
    if (allNeedsMet) {
      const links = [...matched].map((f) => f.title);
      chains.push({ ...rule.make([...matched]), links });
    }
  }
  return chains;
}
