/**
 * ModelStrategyProposer — 반성(reflect) 시 모델에게 "새로 시도할 전략"을 제안받는다.
 *
 * "여러 방법을 스스로 생성"하는 창의성 축. 밴딧은 주어진 전략들 중 고르지만,
 * 새로운 전략 자체를 만드는 건 모델의 몫이다. 여기서 나온 후보는 Explorer 의
 * extraArms 에 추가되어 이후 밴딧의 선택지가 된다(행동공간이 스스로 확장됨).
 */

import type { StrategyProposer, StepRecord } from "./explorer.js";
import type { Observation } from "./env.js";
import type { ModelAdapter } from "../core/types.js";

export class ModelStrategyProposer implements StrategyProposer {
  constructor(
    private readonly model: ModelAdapter,
    /** 실행 가능한 전략만 나오도록 허용 목록으로 필터(예: 등록된 툴 이름) */
    private readonly allowed?: (name: string) => boolean,
  ) {}

  async propose(obs: Observation, history: StepRecord[]): Promise<string[]> {
    const tried = [...new Set(history.map((h) => h.action))];
    const failedHere = history.filter((h) => h.stateKey === obs.stateKey && h.reward <= 0).map((h) => h.action);

    const system =
      "너는 인가된 침투테스트 조수다. 막힌 상황을 벗어날 '새로운' 시도 전략을 제안한다. " +
      "이미 실패한 전략은 반복하지 않는다. 응답은 전략 이름 문자열 배열 JSON 만.";
    const prompt = JSON.stringify({
      state: obs.description,
      facts: obs.facts,
      available_now: obs.available,
      already_tried: tried,
      failed_in_this_state: failedHere,
      instruction: "이 상태에서 진전을 만들 새 전략 1~3개를 제안. 예: ['sqli_probe','ssrf_probe']",
      response_schema: "string[]",
    });

    let raw: string;
    try {
      raw = await this.model.complete({ system, prompt, json: true });
    } catch {
      return [];
    }
    return parseList(raw)
      .filter((s) => !failedHere.includes(s))
      .filter((s) => (this.allowed ? this.allowed(s) : true))
      .slice(0, 3);
  }
}

function parseList(raw: string): string[] {
  try {
    const s = raw.indexOf("[");
    const e = raw.lastIndexOf("]");
    if (s < 0 || e < 0) return [];
    const arr = JSON.parse(raw.slice(s, e + 1));
    return Array.isArray(arr) ? arr.map((x) => String(x)).filter(Boolean) : [];
  } catch {
    return [];
  }
}
