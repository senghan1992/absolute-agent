/**
 * 벤치마크용 취약/견고 참조 앱.
 *
 * RedCell 의 탐지 정확도를 "실제 취약점이 있는 앱"과 "잘 설정된 앱" 양쪽에 대해 측정한다.
 *   - mode "vuln"     : 각 취약점이 실제로 존재 → 탐지율(recall)/재현율 측정
 *   - mode "hardened" : 동일 경로가 안전하게 설정 → 오탐율(false positive) 측정
 *
 * ⚠️ 의도적으로 취약하게 만든 로컬 테스트 서버다. 인가된 벤치마크 용도로만 쓴다.
 */

import http from "node:http";
import { URL } from "node:url";
import { createHmac, randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";

export type Mode = "vuln" | "hardened";

function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}
function signHs256(header: object, payload: object, secret: string): string {
  const h = b64url(header);
  const p = b64url(payload);
  const sig = createHmac("sha256", secret).update(`${h}.${p}`).digest("base64url");
  return `${h}.${p}.${sig}`;
}

// 약한 시크릿("secret")으로 서명 + exp 없음 → jwt_audit 가 high 로 잡아야 함(취약).
const WEAK_JWT = signHs256({ alg: "HS256", typ: "JWT" }, { sub: "1001", user: "alice" }, "secret");
// 강한 무작위 시크릿 + exp 존재 → 취약 설정 없음(견고). /api/me 검증과 같은 시크릿을 쓴다.
const STRONG_JWT_SECRET = randomBytes(32).toString("hex");
const STRONG_JWT = signHs256(
  { alg: "HS256", typ: "JWT" },
  { sub: "1001", iat: 1_700_000_000, exp: 1_700_003_600 },
  STRONG_JWT_SECRET,
);

/** 벤치 앱의 토큰 검증 — vuln: 약한 시크릿 + alg=none 수용(위조 통과) / hardened: 강한 시크릿 + none 거부. */
function verifyJwt(tok: string, hardened: boolean): { user?: string; role?: string } | null {
  const parts = String(tok).split(".");
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")) as { alg?: string };
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as { user?: string; role?: string };
    if (header.alg === "none") return hardened ? null : payload;
    const secret = hardened ? STRONG_JWT_SECRET : "secret";
    const expected = createHmac("sha256", secret).update(`${parts[0]}.${parts[1]}`).digest("base64url");
    return expected === parts[2] ? payload : null;
  } catch {
    return null;
  }
}

function htmlEscape(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

/** 값에서 큰 정수 곱을 실제로 평가(SSTI 취약 템플릿 시뮬). 템플릿 문법은 벗겨낸다. */
function evalArith(v: string): string | null {
  const m = /(\d{2,})\s*\*\s*(\d{2,})/.exec(v);
  if (!m) return null;
  return String(Number(m[1]) * Number(m[2]));
}

/** 경로 조작 값 정규화(%2f 등 반복 디코드) 후 민감 파일 참조 여부. */
function refersPasswd(v: string): boolean {
  let s = v;
  for (let i = 0; i < 2; i++) {
    try {
      s = decodeURIComponent(s);
    } catch {
      break;
    }
  }
  s = s.replace(/%2f/gi, "/").replace(/%5c/gi, "\\");
  return /etc\/passwd/i.test(s) || /win\.ini/i.test(s);
}
function looksMetadata(v: string): boolean {
  return /169\.254\.169\.254|metadata\.google|computeMetadata|2130706433|0177\.0\.0\.1/i.test(v);
}
function hasCmd(v: string): boolean {
  // 구분자 뒤 정보명령(id/whoami) — cmdi 페이로드 시뮬.
  return /(?:[;|&`\n]|\$\(|%0a)\s*(id|whoami)\b/i.test(v) || /`id`|\$\(id\)/i.test(v);
}

const SECURITY_HEADERS: Record<string, string> = {
  "content-security-policy": "default-src 'self'",
  "strict-transport-security": "max-age=63072000",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

const INTROSPECTION = JSON.stringify({
  data: { __schema: { queryType: { name: "Query" }, types: [{ name: "Query", kind: "OBJECT" }, { name: "User", kind: "OBJECT" }] } },
});

export interface RunningApp {
  port: number;
  base: string;
  close: () => Promise<void>;
}

export function startApp(mode: Mode): Promise<RunningApp> {
  const hardened = mode === "hardened";

  const server = http.createServer((req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    const path = u.pathname;
    const q = u.searchParams;
    const origin = req.headers["origin"];

    // 공통 헤더.
    res.setHeader("Server", "nginx/1.18.0");
    res.setHeader("X-Powered-By", "PHP/7.4.3");
    if (hardened) for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);

    const send = (status: number, body: string, headers: Record<string, string> = {}) => {
      for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
      res.statusCode = status;
      res.end(body);
    };

    // ── HTTP 메서드 감사(http_method_audit) ─────────────────────────────────
    // 취약: 위험 메서드 노출 + TRACE 에코(XST). 견고: 안전 메서드만 + TRACE 차단.
    if (req.method === "OPTIONS") {
      res.setHeader("Allow", hardened ? "GET, POST, HEAD, OPTIONS" : "GET, POST, PUT, DELETE, PATCH, TRACE, OPTIONS");
      return send(hardened ? 204 : 200, "");
    }
    if (req.method === "TRACE") {
      if (hardened) return send(405, "Method Not Allowed");
      // 요청 라인 + 헤더를 그대로 에코(XST 시뮬).
      const echo = `TRACE ${req.url} HTTP/1.1\n` + Object.entries(req.headers).map(([k, v]) => `${k}: ${v}`).join("\n");
      return send(200, echo, { "content-type": "message/http" });
    }

    // ── Host 헤더 주입(host_header_audit) ────────────────────────────────────
    // 취약: X-Forwarded-Host/Host 를 절대 URL(비밀번호 재설정 링크)에 그대로 반영.
    if (path === "/reset") {
      const fwd = req.headers["x-forwarded-host"];
      const effective = hardened ? "app.example.com" : String(fwd ?? req.headers["host"] ?? "app.example.com");
      return send(
        200,
        `<html><body>비밀번호 재설정 링크를 보냈습니다.
        <a href="https://${effective}/reset/confirm?token=abc123">여기</a>를 누르세요.</body></html>`,
      );
    }

    // ── 접근통제 미흡(access_control_probe) ──────────────────────────────────
    // 취약: 관리 패널이 무인증 200. 견고: 403.
    if (path === "/admin" || path === "/admin/users") {
      if (hardened) return send(403, "Forbidden");
      return send(
        200,
        `<html><body><h1>Admin Dashboard</h1><h2>User Management</h2>
        <p>manage users below</p>
        <script>var data = {"users":[{"id":1,"role":"admin"},{"id":2,"role":"user"}]};</script>
        </body></html>`,
      );
    }

    // ── HTTP 파라미터 오염(param_pollution) ─────────────────────────────────
    // 취약: 중복 파라미터의 모든 값을 이어붙여 반영. 견고: 첫 값만.
    if (path === "/hpp") {
      const all = q.getAll("q");
      const val = hardened ? (q.get("q") ?? "") : all.join(",");
      return send(200, `<html><body>Query: ${htmlEscape(val)}</body></html>`);
    }

    // ── 인덱스: 크롤 가능한 링크 + 세션 쿠키 + JWT ──────────────────────────
    if (path === "/") {
      res.setHeader(
        "Set-Cookie",
        hardened ? "SESSIONID=abc123; HttpOnly; Secure; SameSite=Lax" : "PHPSESSID=abc123", // 취약: 플래그 없음
      );
      const jwt = hardened ? STRONG_JWT : WEAK_JWT;
      return send(
        200,
        `<html><body>DVWA-bench
        <a href="/search?q=1">search</a> <a href="/item?id=1">item</a> <a href="/tpl?name=x">tpl</a>
        <a href="/ping?host=1">ping</a> <a href="/download?file=a">download</a> <a href="/go?url=/">go</a>
        <a href="/fetch?url=/">fetch</a> <a href="/api/orders/1000">order</a>
        <!-- token: ${jwt} --></body></html>`,
      );
    }

    // ── XSS: /search 취약(원문 반사) · /safe-search 견고(이스케이프) ─────────
    if (path === "/search") {
      const v = q.get("q") ?? "";
      return send(200, `<html><body>Results for ${hardened ? htmlEscape(v) : v}</body></html>`);
    }

    // ── SQLi: /item 취약(오류 노출) · hardened(동일 응답, 오류 숨김) ─────────
    if (path === "/item") {
      const id = q.get("id") ?? "1";
      if (!hardened && id.includes("'")) {
        return send(500, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near ''");
      }
      // 견고/정상: id 와 무관하게 동일 응답(불리언/시간 블라인드도 안 통함).
      return send(200, "<html><body>Item detail page (static)</body></html>");
    }

    // ── SSTI: /tpl 취약(산술 평가) ──────────────────────────────────────────
    if (path === "/tpl") {
      const v = q.get("name") ?? "";
      if (!hardened) {
        const evaluated = evalArith(v);
        if (evaluated) return send(200, `<html><body>Hello ${evaluated}</body></html>`); // 원문 제거, 결과만
      }
      return send(200, `<html><body>Hello ${htmlEscape(v)}</body></html>`); // 견고: 문자 그대로
    }

    // ── CMDI: /ping 취약(명령 출력) ─────────────────────────────────────────
    if (path === "/ping") {
      const v = q.get("host") ?? "";
      if (!hardened && hasCmd(v)) {
        return send(200, "PING 1 (1): 56 data bytes\nuid=0(root) gid=0(root) groups=0(root)\n");
      }
      return send(200, `<html><body>Pinging ${htmlEscape(v)}</body></html>`);
    }

    // ── Path Traversal: /download 취약(파일 노출) ───────────────────────────
    if (path === "/download") {
      const v = q.get("file") ?? "";
      if (!hardened && refersPasswd(v)) {
        return send(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n");
      }
      return send(200, `File: ${htmlEscape(v.replace(/[^\w.\-]/g, ""))}`);
    }

    // ── Open Redirect: /go 취약(Location 반사) ──────────────────────────────
    if (path === "/go") {
      const v = q.get("url") ?? "/";
      return send(hardened ? 302 : 302, "", { Location: hardened ? "/" : v });
    }

    // ── SSRF: /fetch 취약(메타데이터 대리 요청) · hardened(반사만) ───────────
    if (path === "/fetch") {
      const v = q.get("url") ?? "";
      if (!hardened && looksMetadata(v)) {
        // 실제로 메타데이터를 가져온 것처럼 서명 노출(보낸 URL 엔 없는 시그니처).
        return send(200, 'ami-id: ami-0abc123\ninstance-id: i-0def456\n{"AccessKeyId":"ASIAEXAMPLE","Token":"xxx"}');
      }
      // 견고/디코이: 단순 반사(요청한 URL 을 그대로 되돌려줌 → SSRF 아님).
      return send(200, `You requested: ${v}`);
    }

    // ── IDOR: /api/orders/:id 취약(무인증 인접객체) · hardened(403) ──────────
    const order = /^\/api\/orders\/(\d+)$/.exec(path);
    if (order) {
      if (hardened) return send(403, "Forbidden");
      const id = order[1];
      return send(200, JSON.stringify({ order: Number(id), item: `SKU-${id}`, owner: `user${id}` }));
    }

    // ── 미끼(decoy): SSTI 원문 에코 — 두 모드 동일(정상 동작) ────────────────
    // 입력을 "그대로" 되돌려주지만 절대 평가하지 않는다. ssti_probe 는 `{{7919*7331}}`
    // 같은 표현식을 보내므로 응답에 원문(7919*7331)은 등장하지만 곱셈 결과(58053589)는
    // 절대 나오지 않는다. 과거 `!includes(EXPR)` 가드를 제거한 뒤에도 결과값(EXPECT)만을
    // 신호로 삼기에 여기서 오탐하지 않아야 한다(FN 회피 개선의 FP 회귀 감시).
    if (path === "/tpl-echo") {
      const v = q.get("name") ?? "";
      return send(200, `<html><body>Hello ${v}</body></html>`); // 원문 그대로(평가 없음)
    }

    // ── 미끼(decoy): 공개 상품 카탈로그 — 두 모드 동일(정상 동작) ────────────
    // 인접 id 가 서로 다른 공개 객체를 반환하지만 개인정보가 없다 → IDOR 이 아니다.
    // 순진한 "서로 다른 200 = IDOR" 판정이면 여기서 오탐한다(회귀 감시).
    const catalog = /^\/catalog\/(\d+)$/.exec(path);
    if (catalog) {
      const id = catalog[1];
      return send(200, JSON.stringify({ id: Number(id), name: `Widget ${id}`, price: 9.99 + Number(id), category: "tools", inStock: true }));
    }

    // ── 미끼(decoy): 관리자 로그인 스플래시 — 두 모드 동일(정상 동작) ─────────
    // 제목은 "Admin Dashboard"지만 실제로는 로그인 폼이라 접근이 막혀 있다.
    // 헤딩 문구만 보고 판정하면 여기서 오탐한다(회귀 감시).
    if (path === "/portal") {
      return send(
        200,
        `<html><head><title>Admin Dashboard</title></head><body>
         <h1>Admin Dashboard</h1><p>Please sign in to continue.</p>
         <form action="/login" method="post">
           <input name="username" type="text"/>
           <input name="password" type="password"/>
           <button>Login</button>
         </form></body></html>`,
      );
    }

    // ── CORS: /api/data 취약(Origin 반사+creds) · hardened(고정) ─────────────
    if (path === "/api/data") {
      if (hardened) {
        res.setHeader("Access-Control-Allow-Origin", "https://app.example.com");
      } else if (typeof origin === "string") {
        res.setHeader("Access-Control-Allow-Origin", origin);
        res.setHeader("Access-Control-Allow-Credentials", "true");
      }
      return send(200, JSON.stringify({ data: [1, 2, 3] }));
    }

    // ── GraphQL: /graphql 취약(introspection) · hardened(비활성) ────────────
    if (path === "/graphql") {
      if (hardened) return send(400, JSON.stringify({ errors: [{ message: "introspection is disabled" }] }));
      return send(200, INTROSPECTION);
    }

    // ── JWT 능동 위조: /api/me 취약(약한 시크릿 + alg=none 수용) · hardened(강한 시크릿 + none 거부)
    if (path === "/api/me") {
      const tok = (req.headers.authorization ?? "").replace(/^Bearer\s+/i, "");
      const payload = verifyJwt(tok, hardened);
      if (!payload) return send(401, JSON.stringify({ error: "unauthorized", detail: "signature invalid" }));
      return send(200, JSON.stringify({ user: payload.user, role: payload.role ?? "user" }));
    }

    // ── secret_scan: /.env 취약 노출 · hardened(404) ────────────────────────
    if (path === "/.env") {
      if (hardened) return send(404, "Not Found");
      return send(200, "APP_KEY=base64:9xQeRk\nDB_PASSWORD=hunter2\nAWS_ACCESS_KEY_ID=AKIAEXAMPLE\n");
    }

    // ── CSRF: /transfer 폼 취약(토큰 없음) · hardened(토큰 존재) ─────────────
    if (path === "/transfer") {
      const token = hardened ? `<input type="hidden" name="csrf_token" value="xyz">` : "";
      return send(200, `<html><body><form method="post" action="/transfer">${token}<input name="amount"><button>Send</button></form></body></html>`);
    }

    // ── upload: /upload 폼 취약(accept 없음) · hardened(accept 제한) ─────────
    if (path === "/upload") {
      const accept = hardened ? ` accept=".png,.jpg"` : "";
      return send(200, `<html><body><form method="post" enctype="multipart/form-data" action="/upload"><input type="file" name="f"${accept}><button>Up</button></form></body></html>`);
    }

    // ── XXE: /xml 취약(내부 엔티티 확장) · hardened(미확장) ─────────────────
    if (path === "/xml" || path === "/api") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        if (!hardened) {
          const ent = /<!ENTITY\s+xxe\s+"([^"]*)">/.exec(body);
          if (ent) {
            const expanded = body.replace(/&xxe;/g, ent[1]).replace(/<!DOCTYPE[\s\S]*?\]>/, "");
            return send(200, `<result>${expanded}</result>`);
          }
        }
        return send(200, "<result>ok</result>"); // 견고: 엔티티 확장 안 함
      });
      return;
    }

    // ── 정상 엔드포인트(디코이) ─────────────────────────────────────────────
    if (path === "/api/status") return send(200, JSON.stringify({ ok: true }));

    return send(404, "Not Found");
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const port = (server.address() as AddressInfo).port;
      resolve({
        port,
        base: `http://127.0.0.1:${port}`,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}
