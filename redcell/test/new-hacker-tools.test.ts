/**
 * 신규 6종 툴(NoSQLi·CRLF·프로토타입 오염·저장형 XSS·업로드 실증·경쟁 조건) 테스트.
 *
 * 듀얼 서버 패턴(취약/안전 http 서버 + 직접 툴 호출, test/p2-new-tools.test.ts 컨벤션):
 *   - 취약 서버: 6개 취약 엔드포인트(+ decoy) — 툴이 실제로 실증을 내는지.
 *   - 안전 서버: 동일 경로가 정상 동작 — 오탐(FN->FP)이 없는지.
 * opt-in 3종은 State 를 직접 만들어 호출한다(파이프라인 승인 흐름은 assault e2e 가 담당).
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import type { ToolContext, ToolResult } from "../src/core/types.js";
import { nosqlProbe } from "../src/tools/nosql-probe.js";
import { crlfProbe } from "../src/tools/crlf-probe.js";
import { protoPollutionProbe } from "../src/tools/proto-pollution-probe.js";
import { storedXssProbe } from "../src/tools/stored-xss-probe.js";
import { uploadVerify } from "../src/tools/upload-verify.js";
import { raceProbe } from "../src/tools/race-probe.js";


let vuln: http.Server, safe: http.Server;
let vulnPort: number, safePort: number;

/** 게시판 저장소(저장형 XSS 용). */
const board: string[] = [];
/** 업로드 저장소 — 저장 URL → 내용. */
const uploads = new Map<string, { content: string; type: string }>();
/** 잔액 계좌(경쟁 조건). */
let balance = 100;
/** 원자 처리 적용 플래그(경쟁 조건 미끼 서버용). */
let atomicApplied = false;

function vulnHandler(): http.RequestListener {
  return (req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    const p = u.pathname;
    const q = u.searchParams;
    const send = (code: number, body: string, headers: Record<string, string> = {}) => {
      for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
      res.statusCode = code;
      res.end(body);
    };

    // 1) NoSQLi: user[$ne]=x 로 로그인 우회(성공 지수 + dashboard).
    //    서버는 주입된 연산자를 실제로 평가한다: $ne/$gt 는 알려진 사용자 집합과,
    //    $regex 는 정규식 매칭으로 판정한다 — ^zzz 처럼 매칭이 안 되는 패턴은 401.
    if (p === "/login") {
      const USERS = ["admin", "alice"];
      const plain = q.get("user");
      const ne = q.get("user[$ne]");
      const gt = q.get("user[$gt]");
      const rx = q.get("user[$regex]");
      let ok = false;
      if (plain != null) ok = USERS.includes(plain);
      else if (ne != null) ok = USERS.some((u) => u !== ne);
      else if (gt != null) ok = USERS.some((u) => u > gt);
      else if (rx != null) {
        try {
          ok = USERS.some((u) => new RegExp(rx).test(u));
        } catch {
          ok = false;
        }
      }
      if (ok) return send(200, `<html><body><h1>Dashboard</h1><p>welcome admin</p></body></html>`);
      return send(401, "<html><body>login failed</body></html>");
    }

    // 2) CRLF: to 파라미터를 Location 헤더에 그대로(디코드 한 번).
    if (p === "/go") {
      // 취약 서버: 파라미터를 헤더에 직접 반영 — CRLF 를 만나면 새 헤더로 분할(시뮬).
      let to = q.get("to") ?? "/";
      // 취약 서버는 이중 인코딩된 CRLF 를 한 번 디코드해 헤더에 반영한다(실제 웹서버 동작 모사).
      try {
        to = decodeURIComponent(to);
      } catch {
        /* keep */
      }
      const lines = to.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      res.setHeader("Location", lines[0] ?? "/");
      for (const line of lines.slice(1)) {
        const m = /^([^:\s]+):\s*(.*)$/.exec(line);
        if (m) res.setHeader(m[1], m[2]);
      }
      res.statusCode = 302;
      return res.end("");
    }
    // 3) 프로토타입 오염: cfg[__proto__][key]=1 브래킷 키를 객체로 병합해 반영(취약).
    if (p === "/merge") {
      const cfg: Record<string, unknown> = { mode: "default" };
      for (const [k, v] of q.entries()) {
        const m = /^cfg\[([^\]]+)\]\[([^\]]+)\]$/.exec(k);
        if (!m) continue;
        const outer = m[1];
        const inner = m[2];
        // __proto__/constructor 는 Object.prototype 이 아닌 고유 키로 수용(취약 모사).
        if (!Object.prototype.hasOwnProperty.call(cfg, outer) || typeof cfg[outer] !== "object" || cfg[outer] === null) {
          cfg[`\u0000${outer}\u0000`] = {};
        }
        const holder = cfg[`\u0000${outer}\u0000`];
        holder[inner] = decodeURIComponent(v);
      }
      return send(200, `<html><body>config: ${JSON.stringify(cfg)}</body></html>`);
    }

    // 4) 저장형 XSS: POST /board → 저장, GET /board → 렌더(이스케이프 없음).
    if (p === "/board" && req.method === "POST") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const m = /(?:^|&)comment=([^&]*)/.exec(body);
        if (m) board.push(decodeURIComponent(m[1].replace(/\+/g, " ")));
        send(200, "<html><body>saved</body></html>");
      });
      return;
    }
    if (p === "/board") {
      const rendered = board.map((c) => `<div class="comment">${c}</div>`).join("");
      return send(200, `<html><body><h2>게시판</h2>${rendered}
        <form method="post" action="/board"><input name="comment"><button>등록</button></form></body></html>`);
    }

    // 5) 업로드: multipart 저장 + 저장 URL 서빙(svg inline).
    if (p === "/upload" && req.method === "POST") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        // 실제 multipart 파서(파일 부분의 끝을 --boundary 경계로 자른다).
        const fn = /filename="([^"]+)"/.exec(body)?.[1] ?? "";
        const ct = /Content-Type: ([^\r\n]+)/.exec(body)?.[1] ?? "text/plain";
        const boundary = /^--([^\r\n]+)/.exec(body)?.[1] ?? "";
        let content = body.split("\r\n\r\n")[1] ?? "";
        if (boundary) content = content.split(`\r\n--${boundary}`)[0];
        uploads.set(`/uploads/${fn}`, { content, type: ct });
        send(200, `<html><body>saved <a href="/uploads/${fn}">here</a></body></html>`);
      });
      return;
    }
    if (p === "/upload") {
      return send(200, `<html><body>
        <form method="post" enctype="multipart/form-data" action="/upload"><input type="file" name="f"><button>Up</button></form>
      </body></html>`);
    }
    const up = /^\/uploads\/(.+)$/.exec(p);
    if (up) {
      const item = uploads.get(p);
      if (!item) return send(404, "nf");
      if (item.type.includes("svg")) res.setHeader("Content-Type", "image/svg+xml");
      else res.setHeader("Content-Type", item.type);
      res.setHeader("Content-Disposition", "inline");
      res.statusCode = 200;
      return res.end(item.content);
    }

    // 6) 경쟁 조건: /balance GET 상태, POST amount=1 차감(비원자).
    if (p === "/balance") {
      if (req.method === "GET") return send(200, `<html><body>balance: ${balance}</body></html>`);
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const amt = Number(/(?:^|&)amount=(\d+)/.exec(body)?.[1] ?? "0");
        setTimeout(() => {
          const cur = balance; // 지연 블록 안에서 읽는다 → 두 요청이 같은 값을 읽을 수 있음
          balance = cur - amt;
          send(200, `<html><body>balance: ${balance}</body></html>`);
        }, 5);
      });
      return;
    }

    // decoy: login-normal (배열 무시), echo-plain (원문 에코), atomic (원자 차감).
    if (p === "/login-normal") {
      const user = q.get("user") ?? "";
      if (user === "admin") return send(200, "<html><body>Dashboard welcome</body></html>");
      return send(401, "<html><body>login failed</body></html>");
    }
    if (p === "/echo-plain") {
      return send(200, `<html><body>${q.get("cfg") ?? ""}</body></html>`);
    }
    if (p === "/atomic") {
      if (req.method === "GET") return send(200, `<html><body>balance: ${balance}</body></html>`);
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        // 원자 처리: 잠금(적용 플래그) — 첫 요청만 한 유닛 차감, 같은 시점의 중복 요청은 거부.
        const amt = Number(/(?:^|&)amount=(\d+)/.exec(body)?.[1] ?? "0");
        if (amt > 0 && !atomicApplied && balance > 0) {
          atomicApplied = true;
          balance -= 1;
        }
        send(200, `<html><body>balance: ${balance}</body></html>`);
      });
      return;
    }

    return send(404, "nf");
  };
}

function safeHandler(): http.RequestListener {
  return (req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    const p = u.pathname;
    const q = u.searchParams;
    const send = (code: number, body: string, headers: Record<string, string> = {}) => {
      for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
      res.statusCode = code;
      res.end(body);
    };

    if (p === "/login") {
      // 배열/연산자 파라미터 무시 — user 값만 평문 비교.
      const user = q.get("user") ?? "";
      if (user === "admin") return send(200, "<html><body>Dashboard welcome</body></html>");
      return send(401, "<html><body>login failed</body></html>");
    }
    if (p === "/go") {
      // 견고 서버: 값을 URL 인코딩해 Location 에 반영 — CRLF 는 %0d%0a 텍스트로만 남는다.
      const enc = encodeURIComponent(q.get("to") ?? "/");
      res.setHeader("Location", enc);
      res.statusCode = 302;
      return res.end("");
    }
    if (p === "/merge") {
      // __proto__/constructor 차단 — 정적 병합만.
      const cfg = { mode: "default" };
      return send(200, `<html><body>config: ${JSON.stringify(cfg)}</body></html>`);
    }
    if (p === "/board") {
      // 저장 후 렌더 시 이스케이프.
      if (req.method === "POST") {
        let body = "";
        req.on("data", (c) => (body += c));
        req.on("end", () => {
          const m = /(?:^|&)comment=([^&]*)/.exec(body);
          if (m) board.push(decodeURIComponent(m[1].replace(/\+/g, " ")));
          send(200, "<html><body>saved</body></html>");
        });
        return;
      }
      const rendered = board.map((c) => `<div class="comment">${c.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</div>`).join("");
      return send(200, `<html><body><h2>게시판</h2>${rendered}
        <form method="post" action="/board"><input name="comment"><button>등록</button></form></body></html>`);
    }
    if (p === "/upload") {
      // multipart 는 거부(allowlist: .png/.jpg 만, 여기선 전부 거부).
      if (req.method === "POST") return send(400, "invalid file type");
      return send(200, `<html><body>
        <form method="post" enctype="multipart/form-data" action="/upload"><input type="file" name="f" accept=".png,.jpg"><button>Up</button></form>
      </body></html>`);
    }
    if (p === "/balance") {
      if (req.method === "GET") return send(200, `<html><body>balance: ${balance}</body></html>`);
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const amt = Number(/(?:^|&)amount=(\d+)/.exec(body)?.[1] ?? "0");
        balance = Math.max(0, balance - Math.min(amt, 1)); // 원자 처리
        send(200, `<html><body>balance: ${balance}</body></html>`);
      });
      return;
    }
    if (p === "/login-normal") {
      const user = q.get("user") ?? "";
      return user === "admin" ? send(200, "<html><body>Dashboard welcome</body></html>") : send(401, "<html><body>login failed</body></html>");
    }
    if (p === "/echo-plain") {
      return send(200, `<html><body>${q.get("cfg") ?? ""}</body></html>`);
    }
    return send(404, "nf");
  };
}

beforeAll(async () => {
  vuln = http.createServer(vulnHandler());
  safe = http.createServer(safeHandler());
  await new Promise<void>((r) => vuln.listen(0, "127.0.0.1", r));
  await new Promise<void>((r) => safe.listen(0, "127.0.0.1", r));
  vulnPort = (vuln.address() as AddressInfo).port;
  safePort = (safe.address() as AddressInfo).port;
});
afterAll(() => {
  vuln.close();
  safe.close();
});

function ctx(port: number): ToolContext {
  return { target: { host: "127.0.0.1", port }, rps: 200 };
}
type Data = { severity?: string; evidence?: string };

describe("nosql_probe", () => {
  it("user[$ne] 우회 + $regex 오라클로 실증(high)", async () => {
    const r: ToolResult = await nosqlProbe.run({ path: "/login", param: "user" }, ctx(vulnPort));
    expect(r.ok).toBe(true);
    const d = r.data as Data;
    expect(d.severity).toBe("high");
    expect(d.evidence).toContain("NoSQL 실증");
  });
  it("정상 로그인(배열 무시)에서는 오탐하지 않는다", async () => {
    const r = await nosqlProbe.run({ path: "/login-normal", param: "user" }, ctx(vulnPort));
    expect(r.ok).toBe(false);
  });
  it("견고 서버에서는 미탐", async () => {
    const r = await nosqlProbe.run({ path: "/login", param: "user" }, ctx(safePort));
    expect(r.ok).toBe(false);
  });
});

describe("crlf_probe", () => {
  it("to 파라미터 CRLF → 응답 헤더 주입 실증(medium/high)", async () => {
    const r: ToolResult = await crlfProbe.run({ path: "/go", param: "to" }, ctx(vulnPort));
    expect(r.ok).toBe(true);
    const d = r.data as Data;
    expect(d.evidence).toContain("CRLF 실증");
  });
  it("인코딩해 반사하는 견고 서버에서는 미탐(본문 반사만 = 클린)", async () => {
    const r = await crlfProbe.run({ path: "/go", param: "to" }, ctx(safePort));
    expect(r.ok).toBe(false);
  });
});

describe("proto_pollution_probe", () => {
  it("cfg 병합 지점 오염 키 반영 → 실증(medium)", async () => {
    const r: ToolResult = await protoPollutionProbe.run({ path: "/merge", param: "cfg" }, ctx(vulnPort));
    expect(r.ok).toBe(true);
    const d = r.data as Data;
    expect(d.evidence).toContain("프로토타입 오염 실증");
  });
  it("원문 에코 decoy(/echo-plain)에서는 미탐", async () => {
    const r = await protoPollutionProbe.run({ path: "/echo-plain", param: "cfg" }, ctx(vulnPort));
    expect(r.ok).toBe(false);
  });
  it("static 병합 견고 서버에서는 미탐", async () => {
    const r = await protoPollutionProbe.run({ path: "/merge", param: "cfg" }, ctx(safePort));
    expect(r.ok).toBe(false);
  });
});

describe("stored_xss_probe (opt-in)", () => {
  it("comment 저장 → /board 렌더 미이스케이프 → 실증(high)", async () => {
    const r: ToolResult = await storedXssProbe.run({ path: "/board", param: "comment" }, ctx(vulnPort));
    expect(r.ok).toBe(true);
    const d = r.data as Data;
    expect(d.severity).toBe("high");
    expect(d.evidence).toContain("저장형 XSS 실증");
  });
  it("이스케이프 렌더 서버에서는 미탐", async () => {
    const r = await storedXssProbe.run({ path: "/board", param: "comment" }, ctx(safePort));
    expect(r.ok).toBe(false);
  });
});

describe("upload_verify (opt-in)", () => {
  it("txt/svg 업로드 → 저장 URL → svg inline 렌더 → 실행 가능 실증(high)", async () => {
    const r: ToolResult = await uploadVerify.run({ path: "/upload" }, ctx(vulnPort));
    expect(r.ok).toBe(true);
    const d = r.data as Data;
    expect(d.severity).toBe("high");
    expect(d.evidence).toContain("업로드 실증");
  });
  it("업로드 거부 서버(400)는 클린", async () => {
    const r = await uploadVerify.run({ path: "/upload" }, ctx(safePort));
    expect(r.ok).toBe(false);
  });
});

describe("race_probe (opt-in)", () => {
  it("비원자 balance 차감: 동시 2요청이 2배 반영 → 실증(high)", async () => {
    // 서버 상태를 알려진 값으로 재설정(테스트 간 독립).
    balance = 100;
    const r: ToolResult = await raceProbe.run({ path: "/balance", param: "amount" }, ctx(vulnPort));
    expect(r.ok).toBe(true);
    const d = r.data as Data;
    expect(d.severity).toBe("high");
    expect(d.evidence).toContain("경쟁 조건 실증");
  });
  it("원자적 처리(/atomic)에서는 실증 미달", async () => {
    balance = 100; // 테스트 간 독립(공유 balance 변수)
    atomicApplied = false; // 이전 테스트가 적용했으면 리셋
    const r = await raceProbe.run({ path: "/atomic", param: "amount" }, ctx(vulnPort));
    expect(r.ok).toBe(false);
  });
  it("민감 파라미터 없으면 대상 없음", async () => {
    const r = await raceProbe.run({ path: "/balance", param: "q" }, ctx(vulnPort));
    expect(r.ok).toBe(false);
  });
});
