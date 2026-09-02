/**
 * BanditStore — ContextualBandit 통계를 디스크에 영속화.
 * 세션이 끝나도 "어떤 상황에서 뭐가 통했는지"가 누적되어, 실행할수록 똑똑해진다.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { ContextualBandit, type BanditSnapshot, type Policy } from "./bandit.js";

export class BanditStore {
  constructor(private readonly file: string) {}

  async load(policy: Policy = "thompson", rng?: () => number): Promise<ContextualBandit> {
    try {
      const raw = await fs.readFile(this.file, "utf8");
      const snap = JSON.parse(raw) as BanditSnapshot;
      return ContextualBandit.fromSnapshot(snap, policy, undefined, rng);
    } catch {
      return new ContextualBandit(policy, undefined, rng);
    }
  }

  async save(bandit: ContextualBandit): Promise<void> {
    await fs.mkdir(path.dirname(this.file), { recursive: true });
    const tmp = `${this.file}.tmp`;
    await fs.writeFile(tmp, JSON.stringify(bandit.snapshot(), null, 2), "utf8");
    await fs.rename(tmp, this.file); // 원자적 교체
  }
}
