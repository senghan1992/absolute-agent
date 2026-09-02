/**
 * RedCell — prime-agent 확장(extension).
 *
 * prime-agent 의 확장 로더가 이 파일을 로드한다:
 *   .prime/agent/extensions/redcell/index.ts  (또는 settings.json extensions[])
 *
 * 이 확장이 하는 일:
 *   1) [안전 핵심] tool_call 훅에서 모든 액션의 대상 호스트를 검사하여
 *      authorization.yaml scope 밖이면 {block:true} 로 차단한다(harness 레벨 가드).
 *   2) 인가된 대상 전용 정찰 툴(recon_http)을 등록한다.
 *   3) /scope, /engage, /playbooks 슬래시 명령을 등록한다.
 *   4) 화이트해커 방법론(PTES/OWASP, 인가·최소영향 원칙) 시스템 프롬프트를 주입한다.
 *
 * 자기발전(self-improvement)은 prime-agent 의 Continual Harness 를 그대로 사용한다:
 *   성공한 공략은 /refine(또는 auto-refine)에 의해 harness_state.json 의
 *   kind:"memory"/"skill" 엔트리로 축적되어, 다음 engagement 에서 프롬프트에 재주입된다.
 *   RedCell 의 SkillMemory 는 이 harness 메모리를 fingerprint 로 색인하는 보조 계층이다.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
// prime-agent(=@earendil-works/pi-coding-agent) 가 런타임에 제공하는 타입.
// 로컬 타입체크용 폴백은 ./pi-types.d.ts 참조.
import { defineTool, type ExtensionAPI, type ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Type } from "@sinclair/typebox";

import { ScopeGuard, type Target } from "../src/scope/scope-guard.js";
import { loadAuthorization } from "../src/scope/load-auth.js";
import { httpProbe } from "../src/tools/http-probe.js";
import { extractHosts, classifyIntent } from "./inspect.js";

const AUTH_PATH = process.env.REDCELL_AUTH ?? ".prime/agent/redcell/authorization.yaml";

const METHODOLOGY = `
# RedCell — 인가된 화이트해커 모드

너는 인가된(authorized) 침투테스트/CTF 조수다. 다음 원칙을 절대 어기지 않는다:
- **Scope 우선**: authorization.yaml 의 allow 에 있는 대상만 다룬다. 확신이 없으면 /scope 로 확인하고, scope 밖이면 시도조차 하지 않는다.
- **최소 영향**: 취약점은 증명(PoC) 최소 범위로만 확인한다. 데이터 전량 덤프, 서비스 중단(DoS), 파괴적 페이로드는 금지.
- **재현 가능성**: 모든 발견은 방어 관점의 재현 절차와 완화책으로 보고한다.

작업 순서(PTES): 정찰(recon) → 열거(enumerate) → 익스플로잇(exploit, 최소영향) → 사후(post) → 보고(report).
각 단계 시작 시, harness 메모리에 축적된 과거 성공 전술(playbook)을 먼저 검토하라.
성공적으로 대상을 공략했다면 /refine 로 그 전술을 메모리에 저장하여 다음에 더 빨리 뚫어라.
`.trim();

export default async function redcell(pi: ExtensionAPI): Promise<void> {
  let guard: ScopeGuard | null = null;
  let authError: string | null = null;

  const ensureGuard = async (): Promise<void> => {
    if (guard || authError) return;
    try {
      guard = await loadAuthorization(AUTH_PATH);
    } catch (e) {
      authError = (e as Error).message;
    }
  };

  // 1) 방법론 시스템 프롬프트 주입.
  pi.appendSystemPrompt?.(METHODOLOGY);

  // 2) [안전 핵심] 모든 tool_call 을 scope 로 게이팅.
  pi.on("tool_call", async (event: any, _ctx: ExtensionContext) => {
    await ensureGuard();
    if (authError) {
      return { block: true, reason: `RedCell: 인가 파일 로드 실패로 모든 액션을 차단합니다. ${authError}` };
    }
    if (!guard) return; // 이론상 도달 불가

    // 이 호출이 건드리는 대상 호스트들을 추출(전용 툴의 host 인자 + ipython/bash 코드 스캔).
    const argsStr = JSON.stringify(event?.arguments ?? event?.args ?? {});
    const hosts = extractHosts(argsStr);
    const intent = classifyIntent(event?.name ?? event?.tool ?? "", argsStr);

    // 대상이 식별되지 않는 순수 로컬 작업(파일읽기 등)은 통과.
    if (hosts.length === 0) return;

    for (const host of hosts) {
      const target: Target = { host, intent };
      const decision = guard.check(target);
      if (!decision.allowed) {
        return {
          block: true,
          reason: `RedCell scope 위반: ${decision.reason} — authorization.yaml 에 없는 대상이므로 차단합니다.`,
        };
      }
    }
    return; // 모든 대상이 인가됨 → 통과
  });

  // 3) 인가된 대상 전용 정찰 툴.
  pi.registerTool?.(
    defineTool({
      name: "recon_http",
      label: "RedCell HTTP Recon",
      description: "인가된 웹 대상에 GET/HEAD 로 접속해 기술스택을 핑거프린팅한다(비파괴, scope 강제).",
      parameters: Type.Object({
        host: Type.String({ description: "대상 호스트/IP (scope 안이어야 함)" }),
        port: Type.Optional(Type.Number()),
        path: Type.Optional(Type.String({ default: "/" })),
      }),
      async execute(_id, params: { host: string; port?: number; path?: string }) {
        await ensureGuard();
        if (!guard) {
          return { content: [{ type: "text", text: `인가 파일 없음: ${authError}` }], details: {}, isError: true } as any;
        }
        const target: Target = { host: params.host, port: params.port, intent: "recon" };
        const d = guard.check(target);
        if (!d.allowed) {
          return { content: [{ type: "text", text: `차단: ${d.reason}` }], details: { blocked: true }, isError: true } as any;
        }
        const res = await httpProbe.run({ path: params.path ?? "/" }, { target, rps: guard.requestsPerSecond });
        return {
          content: [{ type: "text", text: res.summary }],
          details: { fingerprint: res.fingerprint, data: res.data },
          isError: !res.ok,
        } as any;
      },
    }),
  );

  // 4) 슬래시 명령.
  pi.registerCommand?.("scope", {
    description: "현재 인가(scope) 상태를 출력",
    handler: async (ctx: ExtensionContext) => {
      await ensureGuard();
      const msg = authError
        ? `⛔ 인가 파일 없음/오류: ${authError}`
        : `✅ 인가 로드됨: ${AUTH_PATH}\nRPS 제한: ${guard!.requestsPerSecond}/s`;
      ctx.ui?.info?.(msg) ?? console.log(msg);
    },
  });

  pi.registerCommand?.("playbooks", {
    description: "학습된 playbook 개수 및 목록 요약",
    handler: async (ctx: ExtensionContext) => {
      const dir = path.resolve("redcell/knowledge/playbooks");
      let names: string[] = [];
      try {
        names = (await fs.readdir(dir)).filter((f) => f.endsWith(".json"));
      } catch {
        /* ignore */
      }
      const msg = `📚 playbook ${names.length}건 (${dir})`;
      ctx.ui?.info?.(msg) ?? console.log(msg);
    },
  });
}
