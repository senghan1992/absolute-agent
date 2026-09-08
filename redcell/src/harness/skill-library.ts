/**
 * harness/skill-library — RLM 에이전트가 **요청 시** 로드하는 절차 스킬 카탈로그.
 *
 * skills/<name>/SKILL.md (frontmatter name/description + 본문) 를 읽어:
 *   - 시스템 프롬프트에는 **카탈로그(이름+설명)만** 주입(토큰 절약)
 *   - 모델이 rc.skill("pentest-lab") 을 호출하면 그때 전체 본문을 실어 준다
 *
 * 절대 규칙은 그대로: 스킬 본문도 모델 지시일 뿐, 모든 실행은 브로커(ScopeGuard)를 통과한다.
 */

import { promises as fs } from "node:fs";
import path from "node:path";

export interface SkillDoc {
  name: string;
  description: string;
  /** SKILL.md 전체 본문(frontmatter 제거). */
  body: string;
  /** 원본 파일 경로. */
  file: string;
}

export interface SkillCatalogEntry {
  name: string;
  description: string;
}

/** skills 디렉터리 → 스킬 문서 모음. */
export class SkillLibrary {
  private readonly docs = new Map<string, SkillDoc>();

  private constructor(readonly dir: string) {}

  static async load(dir: string): Promise<SkillLibrary> {
    const lib = new SkillLibrary(dir);
    try {
      for (const ent of await fs.readdir(dir, { withFileTypes: true })) {
        if (!ent.isDirectory()) continue;
        const file = path.join(dir, ent.name, "SKILL.md");
        try {
          const raw = await fs.readFile(file, "utf8");
          const doc = parseSkillMd(raw, file);
          if (doc) lib.docs.set(doc.name.toLowerCase(), doc);
        } catch {
          /* SKILL.md 없는 디렉터리는 무시 */
        }
      }
    } catch {
      /* 스킬 디렉터리 없으면 빈 카탈로그 */
    }
    return lib;
  }

  catalog(): SkillCatalogEntry[] {
    return [...this.docs.values()].map((d) => ({ name: d.name, description: d.description }));
  }

  get(name: string): SkillDoc | undefined {
    return this.docs.get(name.toLowerCase()) ?? this.docs.get(name);
  }

  has(name: string): boolean {
    return this.docs.has(name.toLowerCase()) || this.docs.has(name);
  }
}

function parseSkillMd(raw: string, file: string): SkillDoc | null {
  const m = raw.match(/^\s*---\s*\r?\n([\s\S]*?)\r?\n---\s*\r?\n([\s\S]*)$/);
  if (!m) return null;
  const fm = m[1];
  const name = /^name:\s*(.+)$/m.exec(fm)?.[1]?.trim();
  const description = /^description:\s*(.+)$/m.exec(fm)?.[1]?.trim();
  if (!name) return null;
  return { name, description: description ?? "", body: m[2].trim(), file };
}
