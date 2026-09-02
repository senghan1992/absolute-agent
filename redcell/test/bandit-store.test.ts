import { describe, it, expect } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { BanditStore } from "../src/explore/bandit-store.js";
import { ContextualBandit } from "../src/explore/bandit.js";

describe("BanditStore", () => {
  it("저장/로드가 통계를 보존한다(세션 간 학습)", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "redcell-bs-"));
    const file = path.join(dir, "bandit.json");
    const store = new BanditStore(file);

    const b = await store.load("ucb1");
    b.update("recon|http", "http_probe", 1);
    b.update("recon|http", "http_probe", 1);
    b.update("recon|http", "port_scan", 0);
    await store.save(b);

    const b2 = await store.load("ucb1");
    expect(b2.value("recon|http", "http_probe")).toBeCloseTo(1);
    expect(b2.value("recon|http", "port_scan")).toBeCloseTo(0);
    expect(b2.ranking("recon|http")[0].arm).toBe("http_probe");
  });

  it("파일이 없으면 빈 밴딧을 반환", async () => {
    const store = new BanditStore(path.join(os.tmpdir(), "redcell-nope-" + Date.now(), "b.json"));
    const b = await store.load();
    expect(b.ranking("x").length).toBe(0);
  });
});
