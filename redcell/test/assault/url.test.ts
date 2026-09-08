/**
 * assault url — URL 해석/인가 모듈 테스트.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseAssaultUrl, authorizeTarget } from "../../src/assault/url.js";

describe("parseAssaultUrl", () => {
  it("http(s) URL 을 대상 구조로 해석한다(기본 포트·경로)", () => {
    const t = parseAssaultUrl("http://10.13.37.5:8080/app/login");
    expect(t.scheme).toBe("http");
    expect(t.host).toBe("10.13.37.5");
    expect(t.port).toBe(8080);
    expect(t.path).toBe("/app/login");
  });

  it("포트가 없으면 스킴 기본 포트를 쓴다", () => {
    expect(parseAssaultUrl("https://corp.example").port).toBe(443);
    expect(parseAssaultUrl("http://corp.example").port).toBe(80);
    expect(parseAssaultUrl("https://corp.example/").path).toBe("/");
  });

  it("불완전/비 http 입력은 거부한다 (fail-closed)", () => {
    for (const bad of ["ftp://x", "corp.example", "http://", "javascript:alert(1)", ""]) {
      expect(() => parseAssaultUrl(bad)).toThrow();
    }
  });
});

describe("authorizeTarget", () => {
  it("호스트를 인가 목록에 추가하고 두 번째 실행은 추가하지 않는다", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rc-url-"));
    const file = join(dir, "authorization.list");
    writeFileSync(file, "# RedCell 인가 목록\n");

    const r1 = await authorizeTarget(file, parseAssaultUrl("http://10.9.9.9:81/"));
    expect(r1.added).toBe(true);
    const r2 = await authorizeTarget(file, parseAssaultUrl("http://10.9.9.9:81/"));
    expect(r2.added).toBe(false);

    const saved = readFileSync(file, "utf8");
    expect(saved).toContain("10.9.9.9");
    expect(saved).toContain("# RedCell 인가 목록");
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("parseAssaultUrl 호스트 검증", () => {
  it("불량 호스트 표기는 fail-closed 한다", () => {
    expect(() => parseAssaultUrl("http://!!bad host!!/")).toThrow();
    expect(() => parseAssaultUrl("http://?x=1")).toThrow();
  });
});
