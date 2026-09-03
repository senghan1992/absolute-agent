import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { AddressInfo } from "node:net";
import type { Target } from "../src/scope/scope-guard.js";
import type { ToolContext } from "../src/core/types.js";
import { sstiProbe } from "../src/tools/ssti-probe.js";
import { cmdiProbe } from "../src/tools/cmdi-probe.js";
import { xxeProbe } from "../src/tools/xxe-probe.js";
import { csrfAudit } from "../src/tools/csrf-audit.js";
import { uploadProbe } from "../src/tools/upload-probe.js";
import { crawl } from "../src/tools/crawl.js";
import { jwtAudit } from "../src/tools/jwt-audit.js";
import { forge, stackHint } from "../src/core/payload-forge.js";
import { authGet } from "../src/tools/util.js";
import { harvestCredentials, harvestFromResult } from "../src/core/credential-harvest.js";
import { deriveChains } from "../src/report/chains.js";
import { createHmac } from "node:crypto";

let server: http.Server;
let port: number;

async function readBody(req: http.IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

beforeAll(async () => {
  server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    const p = url.pathname;

    // 인증 표면: 쿠키 있어야 200(로그인 뒤 표면 시뮬레이션).
    if (p === "/private") {
      if (/session=/.test(req.headers["cookie"] ?? "")) res.end("secret data");
      else {
        res.statusCode = 401;
        res.end("unauthorized");
      }
      return;
    }

    // SSTI: 템플릿 문법 안의 A*B 를 실제로 평가해서 결과만 반환.
    if (p === "/tpl") {
      const v = url.searchParams.get("name") ?? "";
      const m = /[{$<%#*@(]{1,3}\s*(\d+)\s*\*\s*(\d+)/.exec(v);
      if (m) {
        res.setHeader("content-type", "text/html");
        res.end(`<h1>Hello ${Number(m[1]) * Number(m[2])}</h1>`); // 평가 결과만(원문 미반사)
        return;
      }
      res.end(`<h1>Hello ${v}</h1>`);
      return;
    }

    // 커맨드 인젝션: 구분자+id 면 실제 명령 출력처럼 응답.
    if (p === "/ping") {
      const v = url.searchParams.get("ip") ?? "";
      if (/(;|\||&|`|\$\()\s*id/.test(v)) {
        res.end("PING ok\nuid=33(www-data) gid=33(www-data) groups=33(www-data)\n");
      } else res.end("PING ok");
      return;
    }

    // XXE: 내부 엔티티 정의를 확장해서 반영(외부 엔티티 아님).
    if (p === "/xmlapi") {
      const body = await readBody(req);
      const def = /<!ENTITY\s+xxe\s+"([^"]*)"\s*>/.exec(body);
      let echoed = body;
      if (def) echoed = echoed.replace(/&xxe;/g, def[1]);
      res.setHeader("content-type", "application/xml");
      res.end(`<result>${echoed.replace(/<!DOCTYPE[\s\S]*?\]>/, "")}</result>`);
      return;
    }

    // CSRF: 토큰 없는 POST 폼.
    if (p === "/account") {
      res.setHeader("content-type", "text/html");
      res.setHeader("Set-Cookie", "session=abc; Path=/");
      res.end(`<form method="post" action="/account/update"><input name="email"><button>save</button></form>`);
      return;
    }

    // 업로드 폼(accept 제한 없음).
    if (p === "/uploader") {
      res.setHeader("content-type", "text/html");
      res.end(`<form method="post" action="/upload" enctype="multipart/form-data"><input type="file" name="f"></form>`);
      return;
    }

    // 크롤 대상: 내부 링크 + 폼 + 외부 링크.
    if (p === "/site") {
      res.setHeader("content-type", "text/html");
      res.end(
        `<a href="/products?id=1">p</a><a href="http://evil.example/x">ext</a>` +
          `<form action="/search"><input name="q"></form><a href="/about">about</a>`,
      );
      return;
    }
    if (p === "/products") {
      res.end(`<a href="/products?id=2">next</a>`);
      return;
    }

    res.end("<html>ok</html>");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
});
afterAll(() => server.close());

function ctx(auth?: Record<string, string>): ToolContext {
  const target: Target = { host: "127.0.0.1", port };
  return { target, rps: 200, auth };
}

describe("PayloadForge (창의적 페이로드 생성)", () => {
  it("취약점 부류별로 다양한(중복 없는) 페이로드를 만든다", () => {
    for (const cls of ["xss", "lfi", "ssti", "cmdi", "ssrf", "redirect"] as const) {
      const ps = forge(cls);
      expect(ps.length).toBeGreaterThanOrEqual(4);
      expect(new Set(ps).size).toBe(ps.length); // 중복 없음
    }
  });

  it("WAF 흔적이 있으면 XSS 우회 변형을 앞세운다", () => {
    const clean = forge("xss", {});
    const wafed = forge("xss", { indicators: ["waf:cloudflare"] });
    expect(wafed[0]).not.toBe(clean[0]); // 선두 페이로드가 우회형으로 바뀜
    expect(stackHint({ indicators: ["waf:cloudflare"] }).waf).toBe(true);
  });

  it("스택 힌트에 따라 페이로드가 달라진다(PHP LFI 래퍼, Windows 파일)", () => {
    const php = forge("lfi", { tech: ["php"] });
    expect(php.some((x) => x.startsWith("php://"))).toBe(true);
    const win = forge("lfi", { os: "Windows Server", indicators: ["iis"] });
    expect(win.some((x) => /win\.ini/i.test(x))).toBe(true);
  });
});

describe("P2 신규 취약점 툴", () => {
  it("ssti_probe: 템플릿 산술 평가를 critical(RCE) 로 탐지", async () => {
    const r = await sstiProbe.run({ path: "/tpl", param: "name" }, ctx());
    expect(r.ok).toBe(true);
    expect((r.data as any).severity).toBe("critical");
  });

  it("cmdi_probe: 명령 출력 노출을 critical(RCE) 로 탐지", async () => {
    const r = await cmdiProbe.run({ path: "/ping", param: "ip" }, ctx());
    expect(r.ok).toBe(true);
    expect((r.data as any).severity).toBe("critical");
  });

  it("xxe_probe: 내부 엔티티 확장을 medium 으로 탐지", async () => {
    const r = await xxeProbe.run({ path: "/xmlapi" }, ctx());
    expect(r.ok).toBe(true);
    expect((r.data as any).severity).toBe("medium");
  });

  it("csrf_audit: 토큰 없는 POST 폼을 medium 으로 탐지", async () => {
    const r = await csrfAudit.run({ path: "/account" }, ctx());
    expect(r.ok).toBe(true);
    expect((r.data as any).severity).toBe("medium");
  });

  it("upload_probe: 제한 없는 업로드 폼을 low 로 표시", async () => {
    const r = await uploadProbe.run({ path: "/uploader" }, ctx());
    expect(r.ok).toBe(true);
    expect((r.data as any).severity).toBe("low");
  });

  it("crawl: 실제 링크·폼 파라미터를 endpoint 로 수집(외부 오리진 제외)", async () => {
    const r = await crawl.run({ path: "/site" }, ctx());
    expect(r.ok).toBe(true);
    const inds: string[] = (r.fingerprint?.indicators ?? []) as string[];
    expect(inds.some((i) => /endpoint \/products\?id=/.test(i))).toBe(true);
    expect(inds.some((i) => /endpoint \/search\?q=/.test(i))).toBe(true);
    expect(inds.some((i) => /evil\.example/.test(i))).toBe(false); // 외부 오리진 제외
  });

  it("ssti_probe: 취약하지 않은 경로에서는 오탐하지 않는다", async () => {
    const r = await sstiProbe.run({ path: "/", param: "name" }, ctx());
    expect(r.ok).toBe(false);
  });
});

describe("jwt_audit (토큰 정적 분석)", () => {
  function b64url(o: unknown): string {
    return Buffer.from(JSON.stringify(o)).toString("base64url");
  }
  it("alg=none 토큰을 critical 로 판정", async () => {
    const tok = `${b64url({ alg: "none", typ: "JWT" })}.${b64url({ sub: "1", exp: 9999999999 })}.`;
    const r = await jwtAudit.run({ path: "/nope" }, ctx({ authorization: `Bearer ${tok}` }));
    expect(r.ok).toBe(true);
    expect((r.data as any).severity).toBe("critical");
  });

  it("약한 HMAC 시크릿을 high 로 판정", async () => {
    const h = b64url({ alg: "HS256", typ: "JWT" });
    const pl = b64url({ sub: "1", exp: 9999999999 });
    const sig = createHmac("sha256", "secret").update(`${h}.${pl}`).digest("base64url");
    const tok = `${h}.${pl}.${sig}`;
    const r = await jwtAudit.run({ path: "/nope" }, ctx({ authorization: `Bearer ${tok}` }));
    expect(r.ok).toBe(true);
    expect(["high", "critical"]).toContain((r.data as any).severity);
  });
});

describe("CredentialHarvester (발견 체이닝)", () => {
  it("노출된 JWT 를 Bearer 헤더로 수확한다", () => {
    const tok = "eyJhbGciOi.eyJzdWIiOi.SIG_abc";
    const h = harvestCredentials(`leaked token=${tok} in bundle.js`);
    expect(h.headers["authorization"]).toBe(`Bearer ${tok}`);
  });
  it(".env 노출의 API 키를 x-api-key 로 수확한다", () => {
    const h = harvestFromResult({ summary: "노출된 .env", data: { evidence: 'API_KEY="abcd1234efgh5678"' } });
    expect(h.headers["x-api-key"]).toBe("abcd1234efgh5678");
  });
  it("이미 인가 파일 자격증명이 있으면 덮지 않는다", () => {
    const h = harvestCredentials("access_token: zzzzzzzzzzzz", { authorization: "Bearer keep-me" });
    expect(h.headers["authorization"]).toBeUndefined();
  });
});

describe("AttackChain (조합 위험 도출)", () => {
  it("SSRF+메타데이터 → critical 클라우드 크리덴셜 체인", () => {
    const chains = deriveChains([
      { phase: "exploit", severity: "high", title: "SSRF → 클라우드 메타데이터 접근 (param=url)", detail: "메타데이터 반사", evidence: "AccessKeyId" },
    ] as any);
    expect(chains.length).toBe(1);
    expect(chains[0].severity).toBe("critical");
  });
  it("XSS+오픈리다이렉트 → 세션 탈취 피싱 체인", () => {
    const chains = deriveChains([
      { phase: "exploit", severity: "high", title: "Reflected XSS (param=q)", detail: "반사", evidence: "" },
      { phase: "exploit", severity: "medium", title: "Open Redirect (param=next)", detail: "외부 이동", evidence: "" },
    ] as any);
    expect(chains.some((c) => /세션 탈취/.test(c.title))).toBe(true);
  });
  it("무관한 단일 발견은 체인을 만들지 않는다", () => {
    const chains = deriveChains([{ phase: "recon", severity: "low", title: "보안 헤더 누락", detail: "", evidence: "" }] as any);
    expect(chains.length).toBe(0);
  });
  it("실제 시크릿 노출 없이 'API 명세 노출'만으로 자격증명 재사용 체인을 만들지 않는다", () => {
    const chains = deriveChains([
      { phase: "enumerate", severity: "medium", title: "API 명세 노출 (/graphql)", detail: "", evidence: "" },
    ] as any);
    expect(chains.some((c) => /자격증명 재사용/.test(c.title))).toBe(false);
  });
  it("실제 .env 시크릿 노출 + API 표면이면 자격증명 재사용 체인을 만든다", () => {
    const chains = deriveChains([
      { phase: "enumerate", severity: "high", title: "민감 파일 노출 (.env 환경설정)", detail: "", evidence: "ACCESS_TOKEN=..." },
      { phase: "enumerate", severity: "medium", title: "API 명세 노출 (/graphql)", detail: "", evidence: "" },
    ] as any);
    expect(chains.some((c) => /자격증명 재사용/.test(c.title))).toBe(true);
  });
});

describe("인증 컨텍스트 스레딩", () => {
  const base = () => `http://127.0.0.1:${port}/private`;
  it("ctx.auth 없으면 401(미인증)", async () => {
    const res = await authGet(ctx(), base());
    expect(res.status).toBe(401);
  });
  it("ctx.auth 쿠키가 요청에 실려 로그인 뒤 표면(200)에 도달한다", async () => {
    const res = await authGet(ctx({ cookie: "session=xyz" }), base());
    expect(res.status).toBe(200);
    expect(res.body).toMatch(/secret data/);
  });
});
