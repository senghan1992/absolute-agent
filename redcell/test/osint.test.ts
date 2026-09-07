/**
 * osint.test — '웹 샅샅이 뒤지기' 딥 다이그 검증.
 *
 *  1) extractPageIntel: 이메일·시크릿·API 경로·tech·폼·스크립트 추출이 동작하는가.
 *  2) deepDig: 링크 따라가기·robots/sitemap 얻어걸림·외부 오리진 배제·예산 준수.
 *  3) OsintAgent(auto): 인가 게이트 + 인텔 수집 + 발견(finding) 전환.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { AddressInfo } from "node:net";
import { ScopeGuard, type AuthorizationFile } from "../src/scope/scope-guard.js";
import { extractPageIntel, deepDig, parseRobots, parseSitemap } from "../src/osint/walker.js";
import { OsintAgent, digestIntel } from "../src/osint/agent.js";

let server: http.Server;
let port: number;
let base = "";

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    switch (url.pathname) {
      case "/":
        res.setHeader("Server", "test-server/1.0");
        res.end(`<html><head><title>OSINT Home</title><meta name="generator" content="TestCMS 3.2"></head>
          <body>
            <a href="/about">소개</a><a href="/products?id=1">상품</a><a href="https://external.example.com/x">외부</a>
            <a href="/files/report.pdf">pdf</a>
            <form action="/search"><input name="q" type="text"></form>
            <script src="/app.js"></script>
            연락처: admin@example.com, dev@example.com
            API 키: AKIAIOSFODNN7EXAMPLE11
            <!-- TODO: /internal 디버그 엔드포인트 -->
          </body></html>`);
        return;
      case "/about":
        res.end('<html><title>About</title><p>02-1234-5678</p><script type="application/ld+json">{"@type":"Organization","name":"Example Inc"}</script></html>');
        return;
      case "/robots.txt":
        res.end("User-agent: *\nDisallow: /hidden\nAllow: /products\n");
        return;
      case "/sitemap.xml":
        res.end(`<?xml version="1.0"?><urlset><url><loc>${base}/blog/post1</loc></url><url><loc>https://outer.example.com/x</loc></url></urlset>`);
        return;
      case "/hidden":
        res.end("<html><title>Hidden</title><p>secret=SuperSecretToken123456</p></html>");
        return;
      case "/blog/post1":
        res.end("<html><title>Post1</title><a href='/about'>back</a></html>");
        return;
      case "/app.js":
        res.setHeader("content-type", "application/javascript");
        res.end("const K='password= hunter2hunter2';");
        return;
      case "/search":
        res.end("<html><title>Search</title>no results</html>");
        return;
      default:
        res.statusCode = 404;
        res.end("<html><title>404</title></html>");
        return;
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
  base = `http://127.0.0.1:${port}`;
});
afterAll(() => server.close());

function auth(): AuthorizationFile {
  return {
    engagement: { name: "osint", authorized_from: "2000-01-01", authorized_until: "2999-12-31", authorized_by: "test" },
    scope: { allow: [{ host: "127.0.0.1" }] },
    limits: { max_requests_per_second: 200 },
  };
}
const guard = () => new ScopeGuard(auth());

describe("extractPageIntel (순수 추출)", () => {
  it("이메일·시크릿·API 경로·tech·메타·주석·폼·스크립트를 뽑는다", () => {
    const html =
      '<html><head><title>T</title><meta name="generator" content="Next.js"></head>' +
      '<body><a href="/a">x</a><form action="/login"><input name="user"></form>' +
      '<script src="/bundle.js"></script>mail: a@b.com key=AKIAIOSFODNN7EXAMPLE11 <!-- note --></body></html>';
    const r = extractPageIntel(html, "http://x/");
    const vals = r.intel.map((i) => `${i.kind}:${i.value}`).join("|");
    expect(vals).toContain("email:a@b.com");
    expect(vals).toContain("secret:key=AKIA");
    expect(vals).toContain("tech:Next.js");
    expect(vals).toContain("data:comment: note");
    expect(vals).toContain("meta:generator: Next.js");
    expect(r.forms.join(",")).toContain("login(user)");
    expect(r.scripts).toContain("http://x/bundle.js");
    expect(r.links).toContain("/a");
  });

  it("external origin·mailto·파일 확장자는 링크에서 제외된다", () => {
    const html = '<a href="https://outer.example.com/x">o</a><a href="mailto:x@y.z">m</a><a href="/doc.pdf">p</a><a href="/ok?p=1">k</a>';
    const r = extractPageIntel(html, "http://x/");
    expect(r.links).toEqual(["/ok?p=1"]);
  });
});

describe("deepDig (결정적 다이그)", () => {
  it("같은 오리진을 따라가며 인텔을 모은다 + robots/sitemap 얻어걸림", async () => {
    const r = await deepDig(base + "/", { rps: 200, maxPages: 12, maxDepth: 2 });
    expect(r.crawled).toBeGreaterThanOrEqual(4); // /, /about, /blog/post1, /hidden(robots), /search...
    const intel = r.intel.map((i) => `${i.kind}:${i.value}`).join("|");
    expect(intel).toContain("admin@example.com");
    expect(intel).toContain("dev@example.com");
    expect(intel).toContain("AKIAIOSFODNN7EXAMPLE11"); // 시크릿
    expect(intel).toContain("phone:02-1234-5678");
    expect(intel).toContain("secret:secret=SuperSecretToken123456"); // robots 로 뒤진 /hidden
    expect(intel).toContain("meta:generator: TestCMS 3.2");
    expect(intel).toContain("comment: TODO: /internal 디버그 엔드포인트");
    // 외부 오리진(sitemap 의 outer.example.com)은 요청 자체를 안 한다.
    expect(r.frontier.some((f) => f.includes("outer.example"))).toBe(false);
  });

  it("canFetch 게이트로 scope 밖 요청을 원천 차단한다", async () => {
    // 시드 자체가 게이트에서 거부되면 한 페이지도 방문하지 않는다.
    const r = await deepDig(base + "/", { rps: 200, maxPages: 8, canFetch: () => false });
    expect(r.crawled).toBe(0);
    expect(r.intel).toHaveLength(0);
  });
});

describe("OsintAgent (auto 속도전)", () => {
  it("인가 대상이라면 인텔을 수집해 발견으로 전환한다", async () => {
    const events: string[] = [];
    const agent = new OsintAgent(guard(), null, {
      auto: true,
      onEvent: (e) => events.push(e.text),
    });
    const log = await agent.run({ host: "127.0.0.1", port }, "example.com 고객 연락처와 시크릿 찾기");
    expect(log.findings.length).toBeGreaterThan(0);
    expect(events.some((t) => t.includes("[인텔] 이메일: admin@example.com") || t.includes("[인텄] 이메일: dev@example.com"))).toBe(true);
    // 시크릿(한국어 라벨) + 목표 적중 요약(🎯) 이 같은 라인에 나온다.
    expect(events.some((t) => t.includes("[인텔] 시크릿/자격증명"))).toBe(true);
    expect(events.some((t) => t.includes("[요약]")) && events.some((t) => t.includes("example.com") && t.includes("🎯"))).toBe(true);
    expect(events.some((t) => t.startsWith("[완료]"))).toBe(true);
  });

  it("인가 밖 대상이면 즉시 거부한다(fail-closed)", async () => {
    const agent = new OsintAgent(guard(), null, { auto: true });
    const log = await agent.run({ host: "10.99.99.99", port }, "아무거나");
    expect(log.transcript.some((t) => t.startsWith("[거부]"))).toBe(true);
    expect(log.findings).toHaveLength(0);
  });
});

describe("digestIntel", () => {
  it("요약 라인과 건수를 만든다", () => {
    const d = digestIntel(
      [
        { kind: "email", value: "a@b.com", source: "http://x/" },
        { kind: "secret", value: "k=AKIAIOSFODNN7EXAMPLE11", source: "http://x/" },
      ],
      "AKIAIOSFODNN7EXAMPLE11 검색",
    );
    expect(d).toContain("2건");
    expect(d).toContain("🎯"); // 목표 키워드 적중
    expect(d).toContain("http://x/");
  });
});

describe("parseRobots / parseSitemap", () => {
  it("robots 의 Disallow/Allow 와 sitemap 의 loc 을 같은 오리진으로만 뽑는다", () => {
    const seed = new URL(base + "/");
    expect(parseRobots("User-agent: *\nDisallow: /hidden\nDisallow: http://other/x", seed)).toEqual(["/hidden"]);
    const sm = parseSitemap(`<loc>${base}/blog/post1</loc><loc>https://outer/x</loc>`, seed);
    expect(sm).toEqual(["/blog/post1"]);
  });
});