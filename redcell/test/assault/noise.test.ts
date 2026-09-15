/**
 * 방어자 시점 요약(noise) — 단위 테스트.
 *
 * 세는 값은 요청 수·경로·상태코드뿐이다. 시각·난수를 쓰지 않으므로 같은 표본이면
 * 같은 결과가 나와야 한다(보고서 재현성). 여기서 그 계약을 고정한다.
 */
import { describe, it, expect } from "vitest";
import { createServer } from "node:http";
import { summarizeNoise, toNoiseSample, SIGNATURE_RULES, type NoiseSample } from "../../src/report/noise.js";
import { httpRequest, withHttpObserver } from "../../src/net/http-client.js";

const S = (method: string, path: string, status: number): NoiseSample => ({ method, path, status });

describe("toNoiseSample — 관찰 URL 정규화", () => {
  it("쿼리를 유지해 시그니처 판정이 가능하게 한다", () => {
    const s = toNoiseSample({ method: "get", url: "http://127.0.0.1:8080/search?q=1%20or%201=1", status: 200 });
    expect(s.method).toBe("GET");
    expect(s.path).toBe("/search?q=1%20or%201=1");
    expect(s.status).toBe(200);
  });
  it("파싱 불가한 URL 은 원문을 그대로 둔다(결정적)", () => {
    expect(toNoiseSample({ method: "GET", url: "not a url", status: 0 }).path).toBe("not a url");
  });
});

describe("summarizeNoise — 결정적 집계", () => {
  it("상태코드 묶음을 정확히 센다(401/403 은 차단, 429 는 레이트리밋)", () => {
    const sum = summarizeNoise([
      S("GET", "/a", 200),
      S("GET", "/b", 301),
      S("GET", "/admin", 401),
      S("GET", "/admin", 403),
      S("GET", "/nope", 404),
      S("GET", "/x", 429),
      S("GET", "/x", 500),
      S("GET", "/x", 418),
    ]);
    expect(sum.requests).toBe(8);
    expect(sum.statuses).toEqual({
      ok2xx: 1,
      redirect3xx: 1,
      denied: 2,
      notFound: 1,
      limited: 1,
      other4xx: 1,
      server5xx: 1,
      unanswered: 0,
    });
  });

  it("같은 입력이면 같은 출력(재현성)", () => {
    const samples = [S("GET", "/a", 200), S("GET", "/b", 200), S("GET", "/a", 403)];
    const first = summarizeNoise(samples);
    const second = summarizeNoise(samples);
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });

  it("상위 경로는 요청 수 내림차순, 동률이면 경로 사전순", () => {
    const sum = summarizeNoise([
      S("GET", "/b", 200), S("GET", "/a", 200), S("GET", "/b", 200), S("GET", "/c", 200),
    ], { top: 2 });
    expect(sum.topPaths.map((p) => p.path)).toEqual(["/b", "/a"]);
    expect(sum.topPaths[0].count).toBe(2);
  });

  it("경로의 대표 상태코드는 최다 득표, 동률이면 작은 코드", () => {
    const sum = summarizeNoise([S("GET", "/p", 500), S("GET", "/p", 200), S("GET", "/p", 200)]);
    expect(sum.topPaths[0]).toEqual({ path: "/p", status: 200, count: 3 });
    const tie = summarizeNoise([S("GET", "/p", 500), S("GET", "/p", 403)]);
    expect(tie.topPaths[0].status).toBe(403);
  });

  it("시그니처성 페이로드를 URL 에서 센다(사실 기록)", () => {
    const sum = summarizeNoise([
      S("GET", "/search?q=' OR 1=1--", 500),
      S("GET", "/file?p=../../etc/passwd", 200),
      S("GET", "/ok?x=1", 200),
    ]);
    expect(sum.signatureHits).toBe(2);
    expect(sum.signatures.length).toBe(2);
    expect(sum.signatures.every((s) => s.count === 1)).toBe(true);
  });

  it("응답을 못 받은 시도도 요청 수에 포함한다(무응답)", () => {
    const sum = summarizeNoise([S("GET", "/slow", 0), S("GET", "/ok", 200)]);
    expect(sum.requests).toBe(2);
    expect(sum.statuses.unanswered).toBe(1);
    expect(sum.notes.join(" ")).toContain("2");
  });

  it("요청 0건이면 관찰 신호 없음으로 요약한다", () => {
    const sum = summarizeNoise([]);
    expect(sum.requests).toBe(0);
    expect(sum.topPaths).toEqual([]);
    expect(sum.signatures).toEqual([]);
    expect(sum.notes.join(" ")).toContain("0건");
  });

  it("차단·레이트리밋·5xx 는 인계 문장으로 남는다(은폐 아님)", () => {
    const sum = summarizeNoise([S("GET", "/a", 403), S("GET", "/b", 429), S("GET", "/c", 500)]);
    const joined = sum.notes.join("\n");
    expect(joined).toContain("401/403");
    expect(joined).toContain("429");
    expect(joined).toContain("5xx");
  });

  it("시그니처 규칙은 본문 없이 URL 만 본다(자격증명 미포함)", () => {
    const sum = summarizeNoise([S("POST", "/login", 200)]);
    expect(sum.signatureHits).toBe(0);
    expect(SIGNATURE_RULES.length).toBeGreaterThan(5);
  });
});

describe("관찰자 격리 — 동시 실행 경계", () => {
  it("동시에 돈 두 실행은 서로의 요청을 세지 않는다", async () => {
    const server = createServer((_req, res) => { res.writeHead(200, { "content-type": "text/plain" }); res.end("ok"); });
    await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
    const port = (server.address() as { port: number }).port;
    const url = `http://127.0.0.1:${port}/`;

    const run = (n: number) => {
      const samples: NoiseSample[] = [];
      return withHttpObserver((o) => samples.push(toNoiseSample(o)), async () => {
        for (let i = 0; i < n; i++) await httpRequest(`${url}p/${i}`);
        return samples;
      });
    };

    const [a, b] = await Promise.all([run(3), run(5)]);
    expect(a.length).toBe(3); // 자기 실행의 요청만
    expect(b.length).toBe(5);
    expect(summarizeNoise(a).statuses.ok2xx).toBe(3);
    expect(summarizeNoise(b).statuses.ok2xx).toBe(5);

    // 실행 범위 밖 요청은 어느 관찰자에게도 가지 않는다(누수 없음).
    await httpRequest(`${url}outside`);
    expect(a.length).toBe(3);
    expect(b.length).toBe(5);

    await new Promise<void>((ok) => server.close(() => ok()));
  });
});
