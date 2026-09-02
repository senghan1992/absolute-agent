import { describe, it, expect, beforeEach } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { SkillMemory, similarity, versionMatch, confidence } from "../src/memory/skill-memory.js";

async function tmpDir(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "redcell-mem-"));
}

describe("similarity / versionMatch", () => {
  it("same service scores high", () => {
    const s = similarity({ service: "nginx", version: "1.18" }, { service: "nginx", version: "1.18.0" });
    expect(s).toBeGreaterThan(0.7);
  });
  it("different service scores 0", () => {
    expect(similarity({ service: "nginx" }, { service: "apache" })).toBe(0);
  });
  it("versionMatch prefix", () => {
    expect(versionMatch("1.18.0", "1.18")).toBe(true);
    expect(versionMatch("1.18", "1.20")).toBe(false);
  });
  it("confidence is laplace-smoothed", () => {
    expect(confidence({ attempts: 0, successes: 0 })).toBeCloseTo(0.5);
    expect(confidence({ attempts: 10, successes: 10 })).toBeGreaterThan(0.9);
  });
});

describe("SkillMemory self-improvement", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await tmpDir();
  });

  it("distills a new playbook then recalls it", async () => {
    const mem = new SkillMemory(dir);
    await mem.load();
    expect(mem.all().length).toBe(0);

    await mem.distill({
      title: "nginx path traversal",
      phase: "exploit",
      match: { service: "nginx", version: "1.18", tech: ["php"] },
      steps: [{ action: "test ../ traversal" }],
    });

    const fresh = new SkillMemory(dir);
    await fresh.load();
    const recalled = fresh.recall({ service: "nginx", version: "1.18", tech: ["php"] }, "exploit");
    expect(recalled.length).toBe(1);
    expect(recalled[0].playbook.source).toBe("distilled");
  });

  it("reinforces instead of duplicating near-identical playbooks", async () => {
    const mem = new SkillMemory(dir);
    await mem.load();
    const input = {
      title: "sqli",
      phase: "exploit" as const,
      match: { service: "http", tech: ["php", "mysql"] },
      steps: [{ action: "probe injection", tool: "sqli" }],
    };
    await mem.distill(input);
    await mem.distill(input); // same shape → should reinforce, not add
    expect(mem.all().length).toBe(1);
    expect(mem.all()[0].attempts).toBeGreaterThan(1);
  });

  it("record() updates confidence and ranking", async () => {
    const mem = new SkillMemory(dir);
    await mem.load();
    const pb = await mem.distill({
      title: "x",
      phase: "recon",
      match: { service: "http" },
      steps: [{ action: "probe" }],
    });
    const before = confidence(pb);
    await mem.record(pb.id, "failure");
    const after = confidence(mem.all()[0]);
    expect(after).toBeLessThan(before);
  });
});
