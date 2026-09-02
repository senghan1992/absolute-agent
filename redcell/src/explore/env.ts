/**
 * LabEnv — 탐색 환경 추상화(Gym 유사).
 *
 * 에이전트는 이 인터페이스만 알면 된다. 뒤에는 시뮬레이션 랩이 올 수도,
 * 실제 인가된 대상을 감싼 어댑터가 올 수도 있다(RealTargetEnv 는 별도 어댑터).
 *
 * 자기발전을 "측정 가능"하게 만드는 것이 목적: reward 와 done 신호가 있으면
 * 에피소드를 반복하며 성공률/스텝수의 개선을 정량적으로 볼 수 있다.
 */

export interface StepResult {
  observation: Observation;
  reward: number; // 이 액션의 즉시 보상
  done: boolean; // 목표 달성 또는 종료
  info: Record<string, unknown>;
}

export interface Observation {
  /** 현재 상태를 식별하는 이산 키(컨텍스트 밴딧의 context 로 쓰인다) */
  stateKey: string;
  /** 사람이 읽는 상태 설명 */
  description: string;
  /** 이 상태에서 시도 가능한 액션(전략) id 목록 */
  available: string[];
  /** 관측된 단서(fingerprint 유사) */
  facts: string[];
}

export interface LabEnv {
  name: string;
  reset(): Observation;
  /** 동기(시뮬레이션) 또는 비동기(실대상 툴 실행) 모두 허용 */
  step(action: string): StepResult | Promise<StepResult>;
  /** 지금까지 이 에피소드에서 밟은 스텝 수 */
  readonly steps: number;
}

/**
 * MockWebLab — 숨겨진 공략 체인을 가진 시뮬레이션 웹 대상.
 *
 * 정답 경로(에이전트는 모름): recon → find_admin → sqli_probe → dump_flag
 * 각 단계에서 "맞는 액션"만 다음 상태로 진행시킨다. 다른 액션은 소폭 감점.
 * 함정(rabbit hole)도 넣어 탐색의 의미를 만든다: xss_probe 는 그럴듯하지만 막다른 길.
 */
export class MockWebLab implements LabEnv {
  name = "mock-web-lab";
  steps = 0;
  private stage = 0;

  // 각 stage 의 정답 액션과, 그 상태에서 노출되는 액션 후보.
  private readonly chain = [
    { correct: "recon", key: "s0:unknown", desc: "미탐색 웹 서비스", facts: ["http 200"] },
    { correct: "find_admin", key: "s1:recon-done", desc: "nginx/php 확인됨", facts: ["nginx", "php", "phpsessid"] },
    { correct: "sqli_probe", key: "s2:admin-found", desc: "/admin 로그인 폼 발견", facts: ["/admin", "login form", "id param"] },
    { correct: "dump_flag", key: "s3:sqli-open", desc: "id 파라미터에 SQLi 반응", facts: ["error-based sqli", "mysql"] },
  ];

  private readonly candidates = [
    "recon",
    "find_admin",
    "sqli_probe",
    "xss_probe", // 함정: 그럴듯하지만 정답 경로 아님
    "dir_bruteforce", // 유용할 때도 있으나 여기선 비효율
    "dump_flag",
    "brute_login", // 비효율 + 위험(운영자가 통제할 몫)
  ];

  reset(): Observation {
    this.steps = 0;
    this.stage = 0;
    return this.observe();
  }

  private observe(): Observation {
    const s = this.chain[this.stage] ?? this.chain[this.chain.length - 1];
    return {
      stateKey: s.key,
      description: s.desc,
      available: [...this.candidates],
      facts: s.facts,
    };
  }

  step(action: string): StepResult {
    this.steps += 1;
    const cur = this.chain[this.stage];

    if (action === cur.correct) {
      this.stage += 1;
      const done = this.stage >= this.chain.length;
      return {
        observation: this.observe(),
        reward: done ? 1.0 : 0.4, // 정답 진행 보상, 최종 성공 큰 보상
        done,
        info: done ? { flag: "FLAG{sim_sqli_chain_solved}" } : { advanced: true, stage: this.stage },
      };
    }

    // 오답: 함정/비효율에 따라 감점 차등.
    const penalty = action === "xss_probe" || action === "brute_login" ? -0.15 : -0.05;
    return {
      observation: this.observe(),
      reward: penalty,
      done: false,
      info: { deadEnd: true, tried: action },
    };
  }
}
