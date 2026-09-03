/**
 * MockCoder — 모델/네트워크 없이 PythonAgent 루프를 검증하는 규칙기반 코더.
 *
 * 실제 운용에서는 provider(Anthropic 등)로 교체된다. 여기서는 "코드 작성→실행→관찰→
 * 다음 코드" 루프가 실제로 도는지, 발견이 수집되는지, scope/안전 가드가 코드 실행 경로에서도
 * 강제되는지를 오프라인으로 재현한다.
 *
 * 진행: (1) 루트 정찰 → (2) 흔한 취약 파라미터에 SQLi 신호 프로빙(신호 있으면 finding) →
 *      (3) 종료.
 */

import type { ModelAdapter } from "../core/types.js";

export class MockCoder implements ModelAdapter {
  /** 결정적·오프라인·대상응답 무관 → 신뢰되는 코드 생성원(OS 격리 없이 실행 허용). */
  readonly trusted = true;
  private step = 0;

  async complete(input: { system: string; prompt: string; json?: boolean }): Promise<string> {
    const req = safe(input.prompt);
    const attempts: unknown[] = Array.isArray(req?.previous_attempts) ? req.previous_attempts : [];
    const n = attempts.length;

    if (n === 0) {
      // 1) 루트 정찰 — 응답 상태/서버 헤더 관찰.
      return json({
        code: [
          "r = rc.get('/')",
          "rc.log('root status', r.status, 'server', r.headers.get('server'))",
          "print(r.text[:80])",
        ].join("\n"),
        rationale: "루트 응답으로 대상 생존/스택 관찰",
      });
    }

    if (n === 1) {
      // 2) SQLi 신호 프로빙 — 작은따옴표 주입 후 DB 오류 시그니처 확인.
      return json({
        code: [
          "base = rc.get('/item?id=1')",
          "inj = rc.get(\"/item?id=1'\")",
          "rc.log('base', base.status, 'inj', inj.status)",
          "if 'SQL syntax' in inj.text or inj.status == 500:",
          "    rc.finding('SQL Injection (param=id)', severity='high', evidence=inj.text[:120], impact='DB 전체 유출 가능')",
        ].join("\n"),
        rationale: "id 파라미터에 SQL 오류 기반 인젝션 신호 탐지",
      });
    }

    // 3) 종료.
    return json({ done: true });
  }
}

function json(o: unknown): string {
  return JSON.stringify(o);
}
function safe(s: string): any {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}
