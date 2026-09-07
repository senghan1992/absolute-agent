import type { Tool, ToolResult } from "../core/types.js";
import { runPython } from "../py/broker.js";
import type { ScopeGuard } from "../scope/scope-guard.js";

/**
 * 파이썬 심화 실행 툴(공격 모드 전용). 오케스트레이터가 취약점 심화·데이터 추출이 필요할 때
 * 모델이 작성한 파이썬 코드를 `rc` 헬퍼(브로커)로 실행하게 한다. 모든 안전 게이트는 그대로:
 *   - 브로커가 요청마다 ScopeGuard 로 host:port 재확인(scope 밖 → ScopeError).
 *   - runPython 의 정적 위험 스캔 + AST 화이트리스트 + 타임아웃 + 요청 예산.
 *   - OS 격리는 best-effort(데스크톱/Windows 호환) — 격리 백엔드가 있으면 사용하고,
 *     없어도 in-process 샌드박스 + 브로커 게이트로 동작한다.
 * mockCoder/trusted=true 같은 신뢰 경로는 쓰지 않는다(항상 신뢰불가 코드 취급).
 */
export function pythonTool(guard: ScopeGuard): Tool {
  return {
    name: "python_exec",
    description:
      "취약점 심화·데이터 추출용 파이썬 직접 실행(인가 대상 한정). 헬퍼: rc.get/post/http(path), " +
      "rc.tcp(host,port,payload=b'') 배너·맞춤 프로토콜, rc.finding(title,severity,evidence=), rc.log(...). " +
      "직접 네트워크 라이브러리(socket/requests/urllib.request)는 정책상 실행되지 않는다. " +
      "사용 예: 인증우회 페이로드 1차 검증, 추출한 쿠키/토큰으로 보호자원 접근, 다른 포트 banner 확인.",
    intent: "exploit",
    async run(args: Record<string, unknown>, ctx): Promise<ToolResult> {
      const code = typeof args.code === "string" && args.code.trim() ? args.code.trim() : "";
      if (!code) return { ok: false, summary: "python_exec: code(파이썬 소스) 인자가 필요합니다.", data: { logs: [] } };

      const r = await runPython(code, {
        guard,
        target: { host: ctx.target.host, port: ctx.target.port },
        auth: ctx.auth,
        jar: ctx.jar,
        proxy: ctx.proxy,
        timeoutMs: 20000,
        isolation: "best-effort",
      });

      const logs = r.logs;
      const base = `요청 ${r.requests}건${r.blockedRequests ? `·scope차단 ${r.blockedRequests}건` : ""}`;
      if (r.danger) return { ok: false, summary: `안전차단(미실행): ${r.danger}`, data: { logs } };
      if (r.syntax) return { ok: false, summary: `구문 오류(미실행, 수정 필요): ${r.syntax.slice(0, 140)}`, data: { logs } };
      if (!r.ok) {
        const why = r.timedOut ? "타임아웃" : `비정상 종료(code=${r.exitCode})`;
        return { ok: false, summary: `${why} — ${base}${logs.length ? ` · ${logs.join(" | ").slice(0, 200)}` : ""}`, data: { logs } };
      }

      // 발견: 첫 건은 기존 ToolResult.data.title 규약으로, 전체 목록은 data.findings 로 전달한다.
      const first = r.findings[0];
      const findings = r.findings.map((f) => ({
        phase: "exploit" as const,
        severity: f.severity,
        title: f.title,
        detail: "python_exec",
        evidence: f.evidence,
        impact: f.impact,
      }));
      const title = first?.title;
      return {
        ok: true,
        summary: `파이썬 실행 완료 — ${base}${r.findings.length ? `·발견 ${r.findings.length}건` : ""}${logs.length ? ` · ${logs.join(" | ").slice(0, 300)}` : ""}`,
        data: {
          title,
          severity: first?.severity,
          evidence: first?.evidence,
          impact: first?.impact,
          findings,
          logs,
          requests: r.requests,
          blockedRequests: r.blockedRequests,
        },
      };
    },
  };
}