/**
 * SkillMemory — RedCell 의 자기발전(self-improvement) 엔진.
 *
 * 핵심 아이디어(prime-agent 의 "스스로 학습하며 발전" 패러다임을 보안 도메인에 이식):
 *   1) 대상을 fingerprint 한다 (서비스/버전/기술스택).
 *   2) 과거에 저장한 playbook 중 fingerprint 가 맞는 것을 recall 한다.
 *   3) 적용 결과(성공/실패)를 record 하여 playbook 의 confidence 를 갱신한다.
 *   4) 새로 성공한 공략을 distill 하여 재사용 가능한 playbook 으로 저장한다.
 *
 * 결과적으로 "같은 종류의 서비스"를 만날수록 더 빠르고 정확하게 뚫는다.
 * 모든 학습은 로컬 파일에만 저장된다(외부 유출 없음).
 */

import { promises as fs } from "node:fs";
import path from "node:path";

export interface Fingerprint {
  /** 예: "nginx", "apache", "openssh", "wordpress", "postgres" */
  service?: string;
  version?: string;
  /** 부가 기술스택: ["php", "mysql", "jquery-1.4"] */
  tech?: string[];
  os?: string;
  /** 자유 텍스트 지표: 응답 헤더, 배너, 에러 메시지 등 */
  indicators?: string[];
}

export type Phase = "recon" | "enumerate" | "exploit" | "post" | "report";

export interface PlaybookStep {
  action: string; // 사람이 읽는 설명
  tool?: string; // 사용 툴 이름(선택)
  command?: string; // 참고용 명령/요청 스케치(실행은 툴 계층이)
  expect?: string; // 성공 신호
}

export interface Playbook {
  id: string;
  title: string;
  phase: Phase;
  /** 이 playbook 이 적용되는 대상 조건 */
  match: Fingerprint;
  preconditions?: string[];
  steps: PlaybookStep[];
  references?: string[]; // CVE, 문서, write-up 링크 등
  /** 학습 통계 */
  attempts: number;
  successes: number;
  createdAt: string;
  lastUsedAt?: string;
  source: "seed" | "distilled"; // 기본 제공 vs 스스로 학습
  tags?: string[];
}

export interface RecallResult {
  playbook: Playbook;
  score: number; // 매칭 점수(fingerprint 유사도 × confidence)
}

/** Laplace-smoothed 성공률 */
export function confidence(p: Pick<Playbook, "attempts" | "successes">): number {
  return (p.successes + 1) / (p.attempts + 2);
}

export class SkillMemory {
  private cache: Map<string, Playbook> = new Map();

  constructor(private readonly dir: string) {}

  async load(): Promise<void> {
    this.cache.clear();
    let files: string[] = [];
    try {
      files = (await fs.readdir(this.dir)).filter((f) => f.endsWith(".json"));
    } catch {
      await fs.mkdir(this.dir, { recursive: true });
    }
    for (const f of files) {
      try {
        const raw = await fs.readFile(path.join(this.dir, f), "utf8");
        const pb = JSON.parse(raw) as Playbook;
        this.cache.set(pb.id, pb);
      } catch {
        // 손상 파일은 조용히 건너뛴다(학습이 멈추면 안 됨).
      }
    }
  }

  all(): Playbook[] {
    return [...this.cache.values()];
  }

  /**
   * fingerprint 에 맞는 playbook 을 관련도 순으로 반환.
   * 점수 = fingerprint 유사도 × confidence. 임계값 미만은 버린다.
   */
  recall(fp: Fingerprint, phase?: Phase, topK = 5): RecallResult[] {
    const results: RecallResult[] = [];
    for (const pb of this.cache.values()) {
      if (phase && pb.phase !== phase) continue;
      const sim = similarity(pb.match, fp);
      if (sim <= 0) continue;
      results.push({ playbook: pb, score: sim * confidence(pb) });
    }
    results.sort((a, b) => b.score - a.score);
    return results.slice(0, topK);
  }

  /** 적용 결과를 반영하여 통계 갱신 후 저장 */
  async record(id: string, outcome: "success" | "failure"): Promise<void> {
    const pb = this.cache.get(id);
    if (!pb) return;
    pb.attempts += 1;
    if (outcome === "success") pb.successes += 1;
    pb.lastUsedAt = new Date().toISOString();
    await this.persist(pb);
  }

  /**
   * distill — 성공한 engagement 를 새 playbook 으로 압축 저장.
   * 이미 매우 유사한 playbook 이 있으면 새로 만들지 않고 통계만 강화한다
   * (지식 폭증/중복 방지).
   */
  async distill(input: {
    title: string;
    phase: Phase;
    match: Fingerprint;
    steps: PlaybookStep[];
    references?: string[];
    tags?: string[];
  }): Promise<Playbook> {
    const near = this.recall(input.match, input.phase, 1)[0];
    if (near && similarity(near.playbook.match, input.match) >= 0.9 && sameShape(near.playbook.steps, input.steps)) {
      await this.record(near.playbook.id, "success");
      return near.playbook;
    }
    const pb: Playbook = {
      id: `pb_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`,
      title: input.title,
      phase: input.phase,
      match: input.match,
      steps: input.steps,
      references: input.references,
      tags: input.tags,
      attempts: 1,
      successes: 1,
      createdAt: new Date().toISOString(),
      lastUsedAt: new Date().toISOString(),
      source: "distilled",
    };
    this.cache.set(pb.id, pb);
    await this.persist(pb);
    return pb;
  }

  private async persist(pb: Playbook): Promise<void> {
    await fs.mkdir(this.dir, { recursive: true });
    await fs.writeFile(path.join(this.dir, `${pb.id}.json`), JSON.stringify(pb, null, 2), "utf8");
  }
}

/**
 * 두 fingerprint 의 유사도(0~1).
 *
 * 원칙:
 *  - service 는 앵커(gate): 양쪽 다 있고 다르면 즉시 0(적용 불가).
 *  - 각 차원은 "양쪽 모두 정보가 있을 때만" 평균에 포함한다.
 *    한쪽이 비어 있으면 보상도 벌점도 없다(비교 불가로 제외).
 *    → 정보가 없다는 이유로 동일 지문이 저평가되는 문제를 방지.
 *  - 비교 가능한 차원이 하나도 없으면 약한 신호(0.3) 또는 0.
 */
export function similarity(a: Fingerprint, b: Fingerprint): number {
  if (a.service && b.service && a.service.toLowerCase() !== b.service.toLowerCase()) {
    return 0;
  }

  let num = 0;
  let den = 0;

  if (a.service && b.service) {
    num += 0.5; // 여기 도달했으면 service 는 일치
    den += 0.5;
  }
  if (a.version && b.version) {
    num += 0.2 * (versionMatch(a.version, b.version) ? 1 : 0);
    den += 0.2;
  }
  if ((a.tech?.length ?? 0) > 0 && (b.tech?.length ?? 0) > 0) {
    num += 0.2 * jaccard(new Set((a.tech ?? []).map(low)), new Set((b.tech ?? []).map(low)));
    den += 0.2;
  }
  if ((a.indicators?.length ?? 0) > 0 && (b.indicators?.length ?? 0) > 0) {
    num += 0.1 * indicatorOverlap(a.indicators ?? [], b.indicators ?? []);
    den += 0.1;
  }

  if (den === 0) return a.service || b.service ? 0.3 : 0;
  return num / den;
}

function low(s: string): string {
  return s.toLowerCase();
}

function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 0;
  let inter = 0;
  for (const x of a) if (b.has(x)) inter++;
  const union = new Set([...a, ...b]).size;
  return union === 0 ? 0 : inter / union;
}

function indicatorOverlap(a: string[], b: string[]): number {
  if (a.length === 0 || b.length === 0) return 0;
  const bl = b.map(low);
  let hit = 0;
  for (const ind of a.map(low)) {
    if (bl.some((x) => x.includes(ind) || ind.includes(x))) hit++;
  }
  return hit / a.length;
}

/** "1.18.0" 과 "1.18" 처럼 접두 일치를 허용 */
export function versionMatch(a: string, b: string): boolean {
  const pa = a.split(".");
  const pb = b.split(".");
  const n = Math.min(pa.length, pb.length);
  for (let i = 0; i < n; i++) if (pa[i] !== pb[i]) return false;
  return true;
}

function sameShape(a: PlaybookStep[], b: PlaybookStep[]): boolean {
  if (Math.abs(a.length - b.length) > 1) return false;
  const ta = a.map((s) => (s.tool ?? s.action).toLowerCase()).join("|");
  const tb = b.map((s) => (s.tool ?? s.action).toLowerCase()).join("|");
  return ta === tb;
}
