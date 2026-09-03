/**
 * 외부 표준 취약앱 검증용 픽스처 — DVWA / OWASP Juice Shop 의 "실제 경로·파라미터 이름"을
 * 독립적으로 모델링한 다중 취약 앱이다. 기존 bench/vulnapp.ts 와 결정적으로 다른 점:
 *
 *   - 기존 벤치(score.ts)는 각 툴에 정답 경로/파라미터를 직접 먹인다(자기참조) → "배선이
 *     맞다면 탐지되는가"만 측정한다.
 *   - 이 픽스처는 RedCell 을 **블라인드**로 돌린다: crawl 이 스스로 표면을 발견하고,
 *     deriveArgs 가 그걸 인젝션 툴 인자로 자동 배선하고, 그 결과로만 탐지한다. 정답 경로를
 *     주지 않는다 → "실전처럼 아무 힌트 없이 얼마나 잡는가"(재현율)를 측정한다.
 *
 * 경로/파라미터는 실제 DVWA(`/vulnerabilities/sqli/?id=`, `/vulnerabilities/exec/?ip=`, …)와
 * Juice Shop(`/rest/products/search?q=`, `/api/Users/:id`, `/redirect?to=`)의 이름을 본떴다.
 * 라이브 DVWA/Juice Shop 은 이 환경(도커 없음, `juice-shop` npm E404)에서 띄울 수 없어,
 * **재현 가능한 최강의 대체물**로 둔다. 실제 컨테이너가 있으면 같은 러너를 그 대상에 겨눌 수 있다.
 *
 * ⚠️ 의도적으로 취약하게 만든 로컬 테스트 서버다. 인가된 벤치마크 용도로만 쓴다.
 *
 * 심은 취약점(ground truth 는 external.ts 의 PLANTED 와 일치):
 *   탐지 기대(9): SQLi(오류) · 반사 XSS · OS 커맨드 인젝션 · 경로조작/LFI · 오픈 리다이렉트 ·
 *                 IDOR · 노출 VCS(.git) · 보안 헤더 누락 · 취약 세션 쿠키
 *   미탐 기대(3): 저장형 XSS(아키텍처: 단일 요청-응답 반사만) · CSRF(배선: PATH_ONLY 단일경로) ·
 *                 비즈니스 로직(시그니처 없음)
 */

import http from "node:http";
import { URL } from "node:url";
import type { AddressInfo } from "node:net";

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
  return /etc\/passwd/i.test(s);
}

/** 구분자 뒤 정보명령(id/whoami) — cmdi 페이로드 시뮬(파괴적 명령은 반응하지 않음). */
function hasInfoCmd(v: string): boolean {
  return /(?:[;|&`\n]|\$\(|%0a)\s*(id|whoami)\b/i.test(v) || /`id`|\$\(id\)/i.test(v);
}

export interface RunningApp {
  port: number;
  base: string;
  close: () => Promise<void>;
}

/**
 * 저장형 XSS 저장소(프로세스 수명). RedCell 은 POST(저장)→GET(렌더)을 상관하지 않으므로
 * 실제로 취약해도 잡지 못한다(정직한 아키텍처 한계 시연).
 */
const storedComments: string[] = [];

export function startExternalApp(): Promise<RunningApp> {
  const server = http.createServer((req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    const path = u.pathname;
    const q = u.searchParams;
    const method = req.method ?? "GET";

    // 실제 스택처럼 서버 배너만 노출. 보안 헤더는 의도적으로 전부 누락(header_audit 대상).
    res.setHeader("Server", "Apache/2.4.51 (Debian)");
    res.setHeader("X-Powered-By", "PHP/8.1.2");
    // 세션 쿠키에 HttpOnly/Secure/SameSite 전부 누락(cookie_audit 대상). 모든 응답에 실어
    // deriveArgs 가 cookie_audit 을 어느 경로로 배선하든 관측되도록 한다.
    res.setHeader("Set-Cookie", "PHPSESSID=3f8a9b2c1d; path=/");

    const send = (status: number, body: string, headers: Record<string, string> = {}): void => {
      for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
      res.statusCode = status;
      res.end(body);
    };

    // ── 메서드 처리: 위험 메서드/ TRACE 는 안전하게 막는다(method_audit 오탐 방지) ──────
    if (method === "OPTIONS") {
      res.setHeader("Allow", "GET, POST, HEAD, OPTIONS");
      return send(204, "");
    }
    if (method === "TRACE") return send(405, "Method Not Allowed");

    // 저장형 XSS 저장(POST). RedCell 은 이 POST 를 하지 않는다 → 저장 경로는 시연용.
    if (path === "/vulnerabilities/xss_s/" && method === "POST") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const m = /(?:^|&)(?:txtName|mtxMessage|comment)=([^&]*)/.exec(body);
        if (m) storedComments.push(decodeURIComponent(m[1].replace(/\+/g, " ")));
        send(200, "<html><body>저장되었습니다.</body></html>");
      });
      return;
    }
    if (method !== "GET" && method !== "HEAD") return send(405, "Method Not Allowed");

    // ── 인덱스: 크롤 가능한 링크(실제 표면). 순서가 crawl 방문/파라미터 발견 순서를 정한다. ──
    // 앞 4개(param 보유, 방문됨) → sqli/xss_r/exec/fi. 나머지는 링크만(방문 상한 초과).
    if (path === "/" || path === "/index.php") {
      return send(
        200,
        `<html><body><h1>Acme Web Portal</h1>
        <a href="/vulnerabilities/sqli/?id=1">사용자 조회</a>
        <a href="/vulnerabilities/xss_r/?name=guest">인사</a>
        <a href="/vulnerabilities/exec/?ip=127.0.0.1">네트워크 진단</a>
        <a href="/vulnerabilities/fi/?page=home">문서 보기</a>
        <a href="/rest/products/search?q=apple">상품 검색</a>
        <a href="/redirect?to=/home">이동</a>
        <a href="/api/Users/1">내 프로필</a>
        <a href="/vulnerabilities/xss_s/">방명록</a>
        <a href="/vulnerabilities/csrf/">비밀번호 변경</a>
        <a href="/rest/basket/checkout">결제</a>
        </body></html>`,
      );
    }

    // ── SQLi(오류 기반): DVWA /vulnerabilities/sqli/?id ─────────────────────────
    // 오류유발 문자에 MySQL 문법 오류를 노출. 그 외에는 정적 응답(에코 없음 → XSS 오탐 방지).
    if (path === "/vulnerabilities/sqli/") {
      const id = q.get("id") ?? "1";
      if (/['"]/.test(id)) {
        return send(500, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax near ''''");
      }
      return send(200, "<html><body>ID: exists. First name: admin. Surname: admin.</body></html>");
    }

    // ── 반사형 XSS: DVWA /vulnerabilities/xss_r/?name (원문 그대로 반사) ──────────
    if (path === "/vulnerabilities/xss_r/") {
      const name = q.get("name") ?? "";
      return send(200, `<html><body>Hello ${name}</body></html>`); // 미이스케이프 반사
    }

    // ── OS 커맨드 인젝션: DVWA /vulnerabilities/exec/?ip (명령 출력 노출) ─────────
    if (path === "/vulnerabilities/exec/") {
      const ip = q.get("ip") ?? "";
      if (hasInfoCmd(ip)) {
        return send(200, "PING 127.0.0.1: 56 data bytes\nuid=33(www-data) gid=33(www-data) groups=33(www-data)\n");
      }
      return send(200, `<html><body>PING ${ip.replace(/[^\w.\-]/g, "")}</body></html>`);
    }

    // ── 경로 조작 / LFI: DVWA /vulnerabilities/fi/?page (파일 노출) ───────────────
    if (path === "/vulnerabilities/fi/") {
      const page = q.get("page") ?? "";
      if (refersPasswd(page)) {
        return send(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n");
      }
      return send(200, `<html><body>문서: ${page.replace(/[^\w.\-]/g, "")}</body></html>`);
    }

    // ── SQLi(2번째 인스턴스): Juice Shop /rest/products/search?q ─────────────────
    // 오류 기반. sqli_probe 는 첫 확정에서 반환하므로 보통 위 /sqli/ 가 먼저 잡힌다(같은 클래스).
    if (path === "/rest/products/search") {
      const term = q.get("q") ?? "";
      if (/['"]/.test(term)) {
        return send(500, JSON.stringify({ error: { message: "SQLITE_ERROR: unrecognized token near \"'\"" } }));
      }
      return send(200, JSON.stringify({ status: "success", data: [{ id: 1, name: "Apple Juice" }] }));
    }

    // ── 오픈 리다이렉트: Juice Shop /redirect?to (Location 반사) ──────────────────
    if (path === "/redirect") {
      const to = q.get("to") ?? "/";
      return send(302, "", { Location: to }); // 외부 도메인 검증 없음
    }

    // ── IDOR: Juice Shop /api/Users/:id (무인증 인접 객체 + 개인정보) ─────────────
    const user = /^\/api\/Users\/(\d+)$/.exec(path);
    if (user) {
      const id = Number(user[1]);
      return send(
        200,
        JSON.stringify({
          id,
          username: `user${id}`,
          email: `user${id}@juice-sh.op`,
          role: id === 1 ? "admin" : "customer",
        }),
      );
    }

    // ── 노출된 VCS: /.git/config, /.git/HEAD (secret_scan 자체 워드리스트로 도달) ──
    if (path === "/.git/config") {
      return send(200, "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@github.com:acme/portal.git\n");
    }
    if (path === "/.git/HEAD") return send(200, "ref: refs/heads/master\n");

    // ── 저장형 XSS(미탐 기대): GET 은 저장분을 미이스케이프 렌더. RedCell 은 POST→GET 미상관 ──
    if (path === "/vulnerabilities/xss_s/") {
      const rendered = storedComments.map((c) => `<div class="comment">${c}</div>`).join("");
      return send(200, `<html><body><h2>방명록</h2>${rendered}
        <form method="post" action="/vulnerabilities/xss_s/">
          <textarea name="mtxMessage"></textarea><button>등록</button>
        </form></body></html>`);
    }

    // ── CSRF(미탐 기대): 토큰 없는 상태변경 POST 폼. deriveArgs 는 csrf_audit 을 다른
    //    param 경로로 배선하고, 이 페이지는 crawl 방문 상한을 넘어 파싱되지 않는다(배선 한계). ──
    if (path === "/vulnerabilities/csrf/") {
      return send(
        200,
        `<html><body><h2>비밀번호 변경</h2>
        <form method="post" action="/vulnerabilities/csrf/">
          <input name="password_new" type="password">
          <input name="password_conf" type="password">
          <button>변경</button>
        </form></body></html>`,
      );
    }

    // ── 비즈니스 로직(미탐 기대): 음수 수량/가격 조작 결제. 시그니처 기반 탐지 불가. ─────
    if (path === "/rest/basket/checkout") {
      return send(200, JSON.stringify({ status: "ok", note: "quantity/coupon 검증은 서버 로직에 있음(시그니처 없음)" }));
    }

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
