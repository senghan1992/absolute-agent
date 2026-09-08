/**
 * harness/harness-store — RLM 에이전트용 Continual Harness(형식화된 평생 지식).
 *
 * prime-agent 어시스턴트의 harness(memory/skill/prompt 항목 + 근거 기반 refine)를
 * RedCell 에 이식한다. 기존 rc.memo() 평판 마크다운(키:본문, 무가중·무분류)을 대체하는
 * **형식화 지식 계층**:
 *
 *   - 항목 종류: memory(배운 사실/전술) · skill(절차적 지식) · prompt(행동 지침)
 *   - 메타: tags, scope(host 또는 global), source(seed|memo|distilled|reflect),
 *           hits(재사용 횟수) · wins(성공) · fails(실패) — Laplace 성공률 추정
 *   - 검색: 점수 = 용어 일치(0.6) + 최신성 감쇠(0.25) + 성공률(0.15), 상위 K 만 프롬프트 주입
 *   - 영속: ~/.redcell/harness/<scope>.json + global.json, 원자적 쓰기
 *
 * ScopeGuard 는 그대로: 이 계층은 **로컬 파일**에만 기록된다(외부 유출 없음).
 */

import { promises as fs } from "node:fs";
import path from "node:path";

export type HarnessKind = "memory" | "skill" | "prompt";
export type HarnessSource = "seed" | "memo" | "distilled" | "reflect";

export interface HarnessEntry {
  kind: HarnessKind;
  /** 안정 키(같은 키는 텍스트 갱신). 예: sqli-id-param */
  key: string;
  /** 지식 본문(사람/모델이 읽는 텍스트). */
  text: string;
  tags: string[];
  /** "global" 또는 호스트 slug. */
  scope: string;
  source: HarnessSource;
  /** 재사용(recall) 횟수. */
  hits: number;
  /** 재사용 뒤 진전(발견·목표 기여)이 있던 횟수. */
  wins: number;
  /** 재사용 뒤 진전이 없던 횟수. */
  fails: number;
  createdAt: string;
  lastUsedAt: string;
}

export interface HarnessRecall {
  entry: HarnessEntry;
  /** 관련성 점수(0~1). */
  score: number;
}

export interface HarnessUpsert {
  kind: HarnessKind;
  key?: string;
  text: string;
  tags?: string[];
  scope?: string;
  source?: HarnessSource;
}

const VERSION = 1;
const MAX_TEXT_CHARS = 2000;

/** 영구 지식의 검색/주입/갱신/증류(distill) — RLM 에이전트의 평생 학습 계층. */
export class HarnessStore {
  private items: HarnessEntry[] = [];
  private readonly fileGlobal: string;
  private readonly fileScope: string;

  private constructor(
    private readonly dir: string,
    private readonly scope: string,
    fileGlobal: string,
    fileScope: string,
  ) {
    this.fileGlobal = fileGlobal;
    this.fileScope = fileScope;
  }

  /** dir(보통 ~/.redcell/harness)에서 global + scope 파일을 읽어 연다. */
  static async open(dir: string, scope: string): Promise<HarnessStore> {
    const store = new HarnessStore(dir, scope, path.join(dir, "global.json"), path.join(dir, `${slugify(scope)}.json`));
    try {
      const g = JSON.parse(await fs.readFile(store.fileGlobal, "utf8")) as { entries?: HarnessEntry[] };
      for (const e of g.entries ?? []) store.items.push({ ...e, scope: "global" });
    } catch {
      /* 없으면 빈 저장소 */
    }
    try {
      const s = JSON.parse(await fs.readFile(store.fileScope, "utf8")) as { entries?: HarnessEntry[] };
      for (const e of s.entries ?? []) if (e.key) store.items.push({ ...e, scope: store.scope });
    } catch {
      /* 없으면 빈 저장소 */
    }
    return store;
  }

  entries(): HarnessEntry[] {
    return [...this.items];
  }

  get(key: string): HarnessEntry | undefined {
    return this.items.find((e) => e.key === key);
  }

  /** 항목 추가/갱신(같은 키면 텍스트·태그 갱신, 아니면 신규). */
  async upsert(inp: HarnessUpsert): Promise<HarnessEntry> {
    const key = (inp.key ?? slugify(inp.text.split(/\n/)[0]).slice(0, 48)) || `h_${Date.now().toString(36)}`;
    const now = new Date().toISOString();
    const tags = [...new Set((inp.tags ?? []).map((x) => x.toLowerCase()).filter(Boolean))];
    const text = inp.text.slice(0, MAX_TEXT_CHARS);
    const scope = inp.scope ?? this.scope;
    const existing = this.items.find((e) => e.key === key);
    if (existing) {
      existing.kind = inp.kind;
      existing.text = text;
      existing.tags = tags;
      existing.source = inp.source ?? existing.source;
      existing.scope = scope;
      existing.createdAt = existing.createdAt || now;
      existing.lastUsedAt = now;
      await this.save();
      return existing;
    }
    const entry: HarnessEntry = {
      kind: inp.kind,
      key,
      text,
      tags,
      scope,
      source: inp.source ?? "memo",
      hits: 0,
      wins: 0,
      fails: 0,
      createdAt: now,
      lastUsedAt: now,
    };
    this.items.push(entry);
    await this.save();
    return entry;
  }

  /** 관련성 점수 순 상위 recalls(recall 이벤트 + 프롬프트 주입용). 검색 후 hits 증가. */
  async recall(query: string, opts: { max?: number; kinds?: HarnessKind[] } = {}): Promise<HarnessRecall[]> {
    const max = opts.max ?? 10;
    const kinds = opts.kinds ? new Set(opts.kinds) : null;
    const tokens = tokenize(query);
    const scored: HarnessRecall[] = [];
    const now = Date.now();
    for (const e of this.items) {
      if (kinds && !kinds.has(e.kind)) continue;
      const s = scoreEntry(e, tokens, now);
      if (s <= 0) continue;
      scored.push({ entry: e, score: s });
    }
    scored.sort((a, b) => b.score - a.score);
    const top = scored.slice(0, max);
    for (const r of top) {
      r.entry.hits++;
      r.entry.lastUsedAt = new Date().toISOString();
    }
    if (top.length) await this.save();
    return top;
  }

  /** 재사용한 항목들 중 이번 engagement 에 실제로 기여한(발견/진전) 항목. */
  async win(keys: string[]): Promise<void> {
    let dirty = false;
    for (const k of keys) {
      const e = this.get(k);
      if (e) { e.wins++; e.lastUsedAt = new Date().toISOString(); dirty = true; }
    }
    if (dirty) await this.save();
  }

  /** 재사용했지만 진전이 없던(실패) 항목. */
  async fail(keys: string[]): Promise<void> {
    let dirty = false;
    for (const k of keys) {
      const e = this.get(k);
      if (e) { e.fails++; e.lastUsedAt = new Date().toISOString(); dirty = true; }
    }
    if (dirty) await this.save();
  }

  /** 성공한 공략 → memory/skill 항목으로 증류(자기발전). */
  async distill(inp: { title: string; text: string; tags?: string[]; kind?: HarnessKind; scope?: string }): Promise<HarnessEntry> {
    return this.upsert({
      kind: inp.kind ?? "memory",
      key: slugify(inp.title).slice(0, 48) || undefined,
      text: inp.text,
      tags: inp.tags,
      scope: inp.scope,
      source: "distilled",
    });
  }

  /** 프롬프트 주입용 문자열 렌더링. */
  static render(recalls: HarnessRecall[], header = "평생 학습(harness) — 재사용할 지식"): string {
    if (!recalls.length) return "";
    const lines = recalls.map((r) => {
      const wr = ((r.entry.wins + 1) / (r.entry.wins + r.entry.fails + 2)).toFixed(2);
      return `  - [${r.entry.kind}:${r.entry.key}] ${r.entry.text.replace(/\n/g, " ")} (win=${wr})`;
    });
    return `${header}:
${lines.join("\n")}`;
  }

  private async save(): Promise<void> {
    await fs.mkdir(this.dir, { recursive: true });
    const forScope = (scope: string) => this.items.filter((e) => e.scope === scope);
    await writeAtomic(this.fileGlobal, JSON.stringify({ version: VERSION, scope: "global", entries: forScope("global") }, null, 2));
    await writeAtomic(this.fileScope, JSON.stringify({ version: VERSION, scope: this.scope, entries: forScope(this.scope) }, null, 2));
  }
}

async function writeAtomic(file: string, data: string): Promise<void> {
  const tmp = `${file}.tmp`;
  await fs.writeFile(tmp, data, "utf8");
  await fs.rename(tmp, file);
}

export function slugify(s: string): string {
  return s.toLowerCase().replace(/[^\w\uac00-\ud7af-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 64);
}

/** 관련성 점수: 용어 일치(0.6) + 최신성 감쇠(0.25) + Laplace 성공률(0.15). */
function scoreEntry(e: HarnessEntry, tokens: Set<string>, now: number): number {
  const hay = [e.key, ...e.tags, e.text].join(" ").toLowerCase();
  let hit = 0;
  for (const tok of tokens) if (hay.includes(tok)) hit++;
  const term = tokens.size ? hit / Math.min(tokens.size, 3) : 0;
  const days = (now - Date.parse(e.lastUsedAt || e.createdAt)) / 86400000;
  const recency = Math.exp(-Math.max(0, days) / 30);
  const winRate = (e.wins + 1) / (e.wins + e.fails + 2);
  return 0.6 * term + 0.25 * recency + 0.15 * winRate;
}

/** 쿼리(목표+호스트) → 검색 토큰(2자 이상, 한국어 1음절 이상 세트). */
export function tokenize(query: string): Set<string> {
  const out = new Set<string>();
  for (const t of query.toLowerCase().split(/[^\w\uac00-\ud7af]+/)) {
    if (t.length >= 2) out.add(t);
  }
  return out;
}
