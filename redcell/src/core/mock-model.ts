/**
 * MockModel — 모델/네트워크 없이 루프를 검증하기 위한 규칙기반 어댑터.
 * 실제 운용에서는 PrimeAgentModel(또는 Anthropic 등)로 교체한다.
 */

import type { ModelAdapter } from "./types.js";

export class MockModel implements ModelAdapter {
  private turns = 0;

  async complete(_input: { system: string; prompt: string; json?: boolean }): Promise<string> {
    const req = safe(_input.prompt);
    const phase = req?.instruction?.match(/phase=(\w+)/)?.[1];
    const fp = req?.known_fingerprint ?? {};

    this.turns++;
    // recon 단계에서는 http_probe 를 한 번 제안하고, 그 뒤엔 종료.
    if (phase === "recon" && !fp.service) {
      return JSON.stringify({
        tool: "http_probe",
        args: { path: "/" },
        rationale: "웹 응답 헤더로 기술스택 핑거프린팅",
        fromPlaybook: "pb_seed_http_recon",
      });
    }
    // 그 외에는 단계 종료.
    return JSON.stringify({ done: true });
  }
}

function safe(s: string): any {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}
