/**
 * MockModel — 모델/네트워크 없이 루프를 검증하기 위한 규칙기반 어댑터.
 * 실제 운용에서는 PrimeAgentModel(또는 Anthropic 등)로 교체한다.
 *
 * "발산형(divergent) 플래너": 한 단계 안에서 한 가지 방법에 갇히지 않고,
 * 그 단계에 어울리는 여러 공격 벡터를 번갈아 시도한다. 이미 발견한
 * fingerprint/엔드포인트가 있으면 그걸 활용해 다음 툴의 인자를 만든다.
 *
 *   recon:     스택 핑거프린팅 → API 표면·쿠키·포트 등 관찰 벡터를 넓힘
 *   enumerate: 엔드포인트 열거 + 노출 파일/CORS/GraphQL 등 정보 벡터를 넓힘
 *   exploit:   SQLi/XSS/LFI/IDOR/오픈리다이렉트/SSRF 등 서로 다른 취약점을 시도
 *
 * 규칙기반이지만, 각 단계에서 "아직 안 써본" 벡터를 우선 골라 폭넓게 발산한다.
 */

import type { ModelAdapter } from "./types.js";
import type { Fingerprint } from "../memory/skill-memory.js";
import { forge } from "./payload-forge.js";
import { deriveArgs } from "./target-map.js";

/** 목표 문구가 "backend API·정보 수집"을 향하는지. */
const API_INTENT = /(\bapi\b|엔드포인트|endpoint|백엔드|backend|정보|목록|수집|제출|submission|평가|evaluation|채점|score|점수|랭킹|ranking)/i;

/** phase → 그 단계에서 쓰는 툴 intent. */
const PHASE_INTENT: Record<string, string> = {
  recon: "recon",
  enumerate: "enumerate",
  exploit: "exploit",
  post: "post",
};

/**
 * 각 단계에서 시도할 툴의 "발산 순서". 실제 등록된 툴만 사용하며,
 * available_tools 에 없는 이름은 자동으로 건너뛴다.
 * 첫 원소일수록 우선 시도(하지만 이미 써본 건 건너뛴다).
 */
const VECTOR_ORDER: Record<string, string[]> = {
  // waf_detect·crawl 을 앞에 둬서 "WAF 맥락"과 "실제 파라미터"를 먼저 확보 → 이후 페이로드가 정교해짐.
  recon: ["http_probe", "waf_detect", "crawl", "header_audit", "api_discover", "cookie_audit", "jwt_audit"],
  enumerate: ["api_probe", "dir_enum", "port_scan", "secret_scan", "graphql_probe", "cors_audit", "csrf_audit", "upload_probe", "http_method_audit", "host_header_audit", "deserialize_probe", "auth_session_probe"],
  exploit: ["sqli_probe", "xss_probe", "ssti_probe", "cmdi_probe", "idor_probe", "path_traversal", "open_redirect", "ssrf_probe", "xxe_probe", "access_control_probe", "param_pollution", "cache_poison_probe", "logic_probe"],
  post: [],
};

interface AvailTool {
  name: string;
  intent: string;
  description: string;
}

export class MockModel implements ModelAdapter {
  private turns = 0;
  /** 현재 단계에서 이미 제안한 툴(단계가 바뀌면 초기화) → 발산 보장. */
  private phase = "";
  private usedInPhase = new Set<string>();

  async complete(_input: { system: string; prompt: string; json?: boolean }): Promise<string> {
    const req = safe(_input.prompt);
    const phase = req?.instruction?.match(/phase=(\w+)/)?.[1] ?? "recon";
    const goal: string = String(req?.instruction ?? "");
    const fp = req?.known_fingerprint ?? {};
    const indicators: string[] = Array.isArray(fp.indicators) ? fp.indicators : [];
    const avail: AvailTool[] = Array.isArray(req?.available_tools) ? req.available_tools : [];
    const apiIntent = API_INTENT.test(goal);

    this.turns++;

    // 단계가 바뀌면 발산 상태 초기화.
    if (phase !== this.phase) {
      this.phase = phase;
      this.usedInPhase = new Set();
    }

    // recon 첫 수: 스택 핑거프린팅(시드 playbook 재사용) — 이 순서는 고정.
    if (phase === "recon" && !fp.service && this.hasTool(avail, "http_probe")) {
      this.usedInPhase.add("http_probe");
      return JSON.stringify({
        tool: "http_probe",
        args: { path: "/" },
        rationale: "웹 응답 헤더로 기술스택 핑거프린팅",
        fromPlaybook: "pb_seed_http_recon",
      });
    }

    // 이 단계에서 아직 안 써본 벡터를 발산 순서대로 하나 고른다.
    const next = this.pickVector(phase, avail, apiIntent);
    if (!next) return JSON.stringify({ done: true });

    this.usedInPhase.add(next);
    const { args, rationale } = this.paramsFor(next, indicators, apiIntent, fp);
    return JSON.stringify({ tool: next, args, rationale });
  }

  /** 이 단계의 발산 순서에서, 등록되어 있고 아직 안 써본 첫 툴. */
  private pickVector(phase: string, avail: AvailTool[], apiIntent: boolean): string | null {
    const intent = PHASE_INTENT[phase] ?? phase;
    const order = this.orderFor(phase, apiIntent);
    // 등록되어 있고(available), 단계 intent 에 맞고, 아직 안 써본 것.
    const availNames = new Set(avail.filter((t) => t.intent === intent).map((t) => t.name));
    for (const name of order) {
      if (availNames.has(name) && !this.usedInPhase.has(name)) return name;
    }
    // 발산 순서에 없지만 등록된 같은 intent 툴이 남아있으면 그것도 시도(빠짐없이).
    for (const name of availNames) {
      if (!this.usedInPhase.has(name)) return name;
    }
    return null;
  }

  /** 목표 성격에 따라 발산 순서를 살짝 재배치(정보수집 목표면 API 벡터 우선). */
  private orderFor(phase: string, apiIntent: boolean): string[] {
    const base = VECTOR_ORDER[phase] ?? [];
    if (!apiIntent) return base;
    if (phase === "recon") return promote(base, "api_discover");
    if (phase === "enumerate") return promote(base, "api_probe");
    return base;
  }

  /** 발견한 엔드포인트/fingerprint 로 각 벡터의 인자를 만든다. */
  private paramsFor(
    tool: string,
    indicators: string[],
    apiIntent: boolean,
    fp: Fingerprint,
  ): { args: Record<string, unknown>; rationale: string } {
    const endpoints = endpointsFrom(indicators);
    switch (tool) {
      case "api_discover":
        return { args: { path: "/" }, rationale: "프런트엔드가 호출하는 backend API 엔드포인트 발견" };
      case "api_probe":
        return endpoints.length
          ? { args: { paths: endpoints }, rationale: "발견된 엔드포인트의 노출 데이터/민감정보 확인(읽기 전용)" }
          : { args: {}, rationale: "흔한 API 표면 열거" };
      case "cookie_audit":
        return { args: { path: "/" }, rationale: "세션 쿠키의 HttpOnly/Secure/SameSite 플래그 점검" };
      case "cors_audit":
        return { args: { path: endpoints[0] ?? "/" }, rationale: "교차출처 신뢰정책(CORS) 오설정 점검" };
      case "secret_scan":
        return { args: {}, rationale: "노출된 .env/.git/백업 파일 시그니처 스캔" };
      case "graphql_probe":
        return { args: {}, rationale: "GraphQL introspection 스키마 노출 여부 확인" };
      case "dir_enum":
        return { args: {}, rationale: "숨은 경로/관리자 인터페이스 열거" };
      case "sqli_probe":
        // deriveArgs 가 crawl 발견 경로×파라미터를 모두 실어 발산 스윕(단일 경로에 갇히지 않음).
        return { args: deriveArgs("sqli_probe", indicators), rationale: "발견된 여러 경로×파라미터에 SQL 인젝션 신호 발산 탐지" };
      case "xss_probe":
        // fp(스택/WAF) 로 다양한 문맥·우회 변형을 생성해 주입 → "한 가지 마커"에 갇히지 않음.
        return { args: { ...deriveArgs("xss_probe", indicators), payloads: forge("xss", fp) }, rationale: "fp 기반 다변형 반사형 XSS 신호 탐지(무해 마커)" };
      case "path_traversal":
        return { args: { ...deriveArgs("path_traversal", indicators), payloads: forge("lfi", fp) }, rationale: "다중 인코딩·스택별 경로 조작/LFI 시도" };
      case "open_redirect":
        return { args: { ...deriveArgs("open_redirect", indicators), payloads: forge("redirect", fp) }, rationale: "파서혼동 변형으로 오픈 리다이렉트 유도 가능성 확인" };
      case "ssrf_probe":
        return { args: { ...deriveArgs("ssrf_probe", indicators), payloads: forge("ssrf", fp) }, rationale: "내부/메타데이터+우회표기로 SSRF 신호 관찰" };
      case "idor_probe": {
        const args = deriveArgs("idor_probe", indicators);
        return Object.keys(args).length ? { args, rationale: "인접 id 요청으로 접근통제 미흡(IDOR) 탐지" } : { args: {}, rationale: "IDOR 대상 경로 필요" };
      }
      case "access_control_probe":
        // 관리/특권 경로 강제 브라우징(무인증). 자체 기본 경로 목록 + 발견 경로.
        return { args: deriveArgs("access_control_probe", indicators), rationale: "관리 기능 무인증 노출(강제 브라우징) 점검(읽기 전용)" };
      case "param_pollution":
        return { args: deriveArgs("param_pollution", indicators), rationale: "중복 파라미터로 HTTP 파라미터 오염(HPP) 신호 탐지" };
      case "deserialize_probe":
        return { args: deriveArgs("deserialize_probe", indicators), rationale: "쿠키/폼/응답의 직렬화 객체 blob(역직렬화 표면) 시그니처 탐지(비파괴)" };
      case "auth_session_probe":
        return { args: deriveArgs("auth_session_probe", indicators), rationale: "세션 토큰 엔트로피/예측성 + URL 세션ID 노출 점검(읽기 전용)" };
      case "cache_poison_probe":
        return { args: deriveArgs("cache_poison_probe", indicators), rationale: "고유 cache-buster 로 unkeyed 헤더 캐시 포이즈닝 2단계 확인(실사용자 무영향)" };
      case "logic_probe":
        return { args: deriveArgs("logic_probe", indicators), rationale: "가격/수량/권한류 파라미터의 로직 검증 부재 신호 관찰(읽기 전용)" };
      case "http_method_audit":
        return { args: deriveArgs("http_method_audit", indicators), rationale: "위험 HTTP 메서드/ TRACE 에코(XST) 관찰(비파괴)" };
      case "host_header_audit":
        return { args: deriveArgs("host_header_audit", indicators), rationale: "Host/X-Forwarded-Host 반영(재설정·캐시 포이즈닝) 점검" };
      case "waf_detect":
        return { args: { path: "/" }, rationale: "WAF 존재/제조사 파악 → 이후 페이로드 우회 방향 결정" };
      case "crawl":
        return { args: { path: "/" }, rationale: "실제 링크·폼·파라미터 수집(추측 대신 실제 표면)" };
      case "jwt_audit":
        return { args: { path: "/" }, rationale: "세션/토큰 JWT 의 alg·시크릿·수명 정적 분석" };
      case "csrf_audit": {
        const args = deriveArgs("csrf_audit", indicators);
        return { args: Object.keys(args).length ? args : { path: "/" }, rationale: "상태변경 폼의 위조 방지 토큰/ SameSite 방어 관측" };
      }
      case "upload_probe": {
        const args = deriveArgs("upload_probe", indicators);
        return { args: Object.keys(args).length ? args : { path: "/" }, rationale: "파일 업로드 표면과 확장자 제한 관측(비파괴)" };
      }
      case "ssti_probe":
        return { args: deriveArgs("ssti_probe", indicators), rationale: "여러 템플릿 엔진 산술식으로 서버측 템플릿 인젝션 탐지" };
      case "cmdi_probe":
        return { args: { ...deriveArgs("cmdi_probe", indicators), payloads: forge("cmdi", fp) }, rationale: "구분자 변형으로 OS 커맨드 인젝션 탐지" };
      case "xxe_probe":
        return { args: deriveArgs("xxe_probe", indicators), rationale: "XML 엔드포인트에 내부 엔티티로 XXE 처리 가능성 탐지" };
      case "http_probe":
        return { args: { path: "/" }, rationale: "추가 경로 핑거프린팅" };
      case "header_audit":
        return { args: { path: "/" }, rationale: "보안 헤더 누락 점검" };
      case "port_scan":
        return { args: {}, rationale: "노출 서비스 포트 관찰" };
      default:
        return { args: {}, rationale: apiIntent ? "API 표면 조사" : "추가 조사" };
    }
  }

  private hasTool(avail: AvailTool[], name: string): boolean {
    return avail.some((t) => t.name === name);
  }
}

/** 발산 순서에서 특정 툴을 앞으로 끌어올린다. */
function promote(order: string[], name: string): string[] {
  if (!order.includes(name)) return order;
  return [name, ...order.filter((n) => n !== name)];
}

/** fingerprint 지표에서 "endpoint /api/..." 경로만 추출(상한 6개). */
function endpointsFrom(indicators: string[]): string[] {
  const out: string[] = [];
  for (const i of indicators) {
    const m = /^endpoint (\/\S+)/.exec(i);
    if (m) out.push(m[1]);
  }
  return [...new Set(out)].slice(0, 6);
}

function safe(s: string): any {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}
