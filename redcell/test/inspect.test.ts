import { describe, it, expect } from "vitest";
import { extractHosts, classifyIntent } from "../prime-agent/inspect.js";

describe("extractHosts — tool_call 훅의 대상 추출", () => {
  it("URL / IP / localhost 를 뽑아낸다", () => {
    const h = extractHosts(JSON.stringify({ code: "curl http://10.13.37.5:8080/login; ping 8.8.8.8" }));
    expect(h).toContain("10.13.37.5");
    expect(h).toContain("8.8.8.8");
  });
  it("localhost 감지", () => {
    expect(extractHosts("nmap localhost")).toContain("localhost");
  });
  it("파일명/흔한 도메인은 잡음으로 제외", () => {
    const h = extractHosts("read package.json and index.html from github.com");
    expect(h).not.toContain("package.json");
    expect(h).not.toContain("index.html");
    expect(h).not.toContain("github.com");
  });
  it("대상이 없으면 빈 배열(순수 로컬 작업은 통과)", () => {
    expect(extractHosts(JSON.stringify({ path: "/etc/hosts" }))).toEqual([]);
  });
});

describe("classifyIntent — 액션 성격 판정", () => {
  it("파괴적 명령", () => {
    expect(classifyIntent("ipython", "rm -rf /var/www")).toBe("destructive");
    expect(classifyIntent("ipython", "DROP TABLE users")).toBe("destructive");
  });
  it("DoS", () => {
    expect(classifyIntent("bash", "hping3 --flood target")).toBe("dos");
  });
  it("익스플로잇/열거/정찰", () => {
    expect(classifyIntent("ipython", "sqlmap -u ...")).toBe("exploit");
    expect(classifyIntent("ipython", "nmap -sV host")).toBe("enumerate");
    expect(classifyIntent("recon_http", '{"host":"127.0.0.1"}')).toBe("recon");
  });
});
