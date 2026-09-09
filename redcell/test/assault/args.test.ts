
import { describe, it, expect } from "vitest";
import { autoArgsFor } from "../../src/assault/args.js";
import type { Fingerprint } from "../../src/memory/skill-memory.js";

describe("autoArgsFor sqli_probe (발견 경로 전체 스윕)", () => {
  it("첫 endpoint 하나가 아니라 발견 경로 전체를 paths 로 넘긴다", () => {
    const fp: Fingerprint = { indicators: ["endpoint /users/1", "endpoint /search"] };
    const args = autoArgsFor("sqli_probe", fp) as { paths: string[]; params?: string[] };
    expect(args.paths).toContain("/users/1");
    expect(args.paths).toContain("/search");
    expect(args.paths.length).toBe(2);
  });
  it("query 파라미터 힌트가 있으면 params 로 전달한다", () => {
    const fp: Fingerprint = { indicators: ["endpoint /search?q="] };
    const args = autoArgsFor("sqli_probe", fp) as { paths: string[]; params?: string[] };
    expect(args.paths).toContain("/search");
    expect(args.params).toContain("q");
  });
});
