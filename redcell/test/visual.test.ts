/**
 * visual.test.ts — 초보자용 시각 상황판(toVisualBoard).
 *
 * 초보자 3인(보안 신입/웹 개발자/비개발 PM) 사용성 테스트에서 나온 요구를 회귀로 고정한다:
 *   - 한글 우선 제목  - 유형별 고유 설명(복붙 금지)  - 조치 기한·담당
 *   - '위치'는 공격당한 파일(/etc/passwd)이 아니라 취약 엔드포인트  - 게이트 통과 조건 명시.
 */

import { describe, it, expect } from "vitest";
import { toVisualBoard } from "../src/report/visual.js";
import type { EngagementFinding, EngagementLog } from "../src/core/types.js";

function f(sev: EngagementFinding["severity"], title: string, evidence?: string): EngagementFinding {
  return { phase: "exploit", severity: sev, title, detail: "d", evidence };
}
function log(findings: EngagementFinding[], extra: Partial<EngagementLog> = {}): EngagementLog {
  return {
    target: { host: "127.0.0.1", port: 8080 },
    fingerprint: { service: "nginx", version: "1.18.0", tech: ["php"], indicators: ["endpoint /a", "endpoint /b"] },
    findings,
    usedPlaybooks: [],
    distilled: [],
    transcript: [],
    ...extra,
  };
}

describe("상황판 기본 구조", () => {
  it("헤더·신호등·공격경로·위험도·다음할일 섹션이 모두 있다", () => {
    const b = toVisualBoard(log([f("high", "Reflected XSS (param=q)", "(/search) 반사")]));
    expect(b).toContain("초보자 상황판");
    expect(b).toContain("한눈에 보기");
    expect(b).toContain("공격 경로");
    expect(b).toContain("위험도");
    expect(b).toContain("무엇이 문제인가요?");
    expect(b).toContain("그래서, 지금 무엇을 하면 되나요?");
  });

  it("사용 기술은 서비스와 버전을 붙여 보여준다", () => {
    expect(toVisualBoard(log([]))).toContain("nginx 1.18.0");
  });
});

describe("신호등 판정", () => {
  it("발견 있으면 🔴 위험 + 게이트 통과 조건(high+ 잔여 건수) + 경영진 한 줄", () => {
    const b = toVisualBoard(log([f("critical", "OS Command Injection (param=host)", "(path=/ping, payload=;id): uid=0(root)"), f("medium", "Missing Security Headers")]));
    expect(b).toContain("🔴 위험");
    expect(b).toContain("경영진 보고용 한 줄");
    expect(b).toMatch(/오픈\(게이트 통과\) 조건: 심각·높음 0건\. 지금 1건 남음/);
  });

  it("발견 없으면 🟢 양호", () => {
    expect(toVisualBoard(log([]))).toContain("🟢 양호");
  });

  it("inconclusive 는 🟡 판단 보류", () => {
    const b = toVisualBoard(log([], { verdict: "inconclusive", verdictReason: "대상 미도달" }));
    expect(b).toContain("🟡 판단 보류");
    expect(b).toContain("대상 미도달");
  });
});

describe("발견 카드", () => {
  it("영어 제목을 한글 우선 제목으로 바꾼다", () => {
    const b = toVisualBoard(log([f("critical", "Server-Side Template Injection (param=name)", "(path=/tpl, payload={{7*7}})")]));
    expect(b).toContain("서버 템플릿 주입 (SSTI)");
  });

  it("심각도별 조치 기한·담당을 표기한다", () => {
    const b = toVisualBoard(log([f("critical", "OS Command Injection (param=host)", "(path=/ping)")]));
    expect(b).toContain("24시간 내(최우선)");
    expect(b).toContain("개발팀(코드 수정)");
  });

  it("SSTI 와 OS Command Injection 은 서로 다른 설명을 받는다(복붙 금지)", () => {
    const b = toVisualBoard(log([
      f("critical", "Server-Side Template Injection (param=name)", "(path=/tpl)"),
      f("critical", "OS Command Injection (param=host)", "(path=/ping)"),
    ]));
    expect(b).toContain("화면 '틀(템플릿)'");
    expect(b).toContain("진짜 '시스템 명령어'");
  });

  it("API/GraphQL 노출에 '열쇠 폐기' 오조치가 붙지 않는다", () => {
    const b = toVisualBoard(log([f("medium", "GraphQL Introspection 노출 (/graphql)", "introspection 스키마 반환")]));
    expect(b).toContain("API 설계도·관리 경로 노출");
    expect(b).toContain("introspection");
    // 이 카드 영역에 '열쇠·토큰 폐기' 문구가 없어야 한다.
    const card = b.slice(b.indexOf("API 설계도·관리 경로 노출"));
    expect(card.slice(0, 400)).not.toContain("폐기·재발급");
  });
});

describe("위치(엔드포인트) 표기", () => {
  it("공격당한 파일(/etc/passwd)이 아니라 취약 엔드포인트(path=)를 위치로 쓴다", () => {
    const b = toVisualBoard(log([f("high", "Path Traversal / LFI (param=file)", "unix /etc/passwd 노출 (path=/download, payload=../../../../etc/passwd): root:x:0:0")]));
    expect(b).toContain("위치: /download");
    expect(b).not.toContain("위치: /etc/passwd");
  });

  it("SSRF 와 Open Redirect 가 같은 param=url 이어도 경로로 구분된다", () => {
    const b = toVisualBoard(log([
      f("high", "SSRF (param=url)", "메타데이터 반사 (path=/fetch, target=http://169.254.169.254/)"),
      f("medium", "Open Redirect (param=url)", "(path=/go) HTTP 302"),
    ]));
    expect(b).toContain("위치: /fetch");
    expect(b).toContain("위치: /go");
  });
});

describe("실제 확인(근거의 사람 말 요약)", () => {
  it("root 명령 실행 근거는 '최고권한(root)' 한 줄로 풀어준다", () => {
    const b = toVisualBoard(log([f("critical", "OS Command Injection (param=host)", "(path=/ping, payload=;id): uid=0(root) gid=0(root)")]));
    expect(b).toContain("서버 최고권한(root)");
  });
});

describe("수용된 위험(waiver) 표기", () => {
  it("waiver 는 승인자·기한과 함께 별도 표기된다", () => {
    const b = toVisualBoard(log([f("high", "SQL Injection (param=id)")]), {
      waived: [{ finding: f("high", "Missing Security Headers"), waiver: { match: "Missing", reason: "수용", approved_by: "CISO", expires: "2026-12-31" } }],
    });
    expect(b).toContain("알고 넘어가기로");
    expect(b).toContain("CISO");
    expect(b).toContain("2026-12-31");
  });
});
