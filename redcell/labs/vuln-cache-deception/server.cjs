/**
 * vuln-cache-deception — 웹 캐시 기만(Web Cache Deception) 랩.
 *
 *   - /profile        : 세션 쿠키(sid)가 있어야 개인 페이지(no-store). 없으면 302 로그인.
 *   - /profile/*.css  : 서버가 접미사를 무시하고 개인 페이지를 반환하며, 응답을
 *                       `Cache-Control: public, max-age=60` 으로 내보낸다(취약 조합).
 *                       무인증 요청에는 캐시된(=피해자의) 개인 본문이 그대로 나간다.
 *
 * 취약 조합 = "정적 확장자 경로는 공개 캐시 대상" 오판 + "개인 데이터 응답".
 * 학습/검증용 로컬 랩이며 실제 공유 캐시를 오염시키지 않는다.
 */
const http = require("node:http");
const port = Number(process.env.PORT ?? 18114);
const VICTIM = process.env.VICTIM_SID ?? "sid=sid-lee-2026";

const PAGE = (user, email) =>
  `<!doctype html><html><body><h1>마이페이지</h1><p>안녕하세요 ${user} 님</p><p>이메일: ${email}</p>` +
  `<ul><li>권한: 일반 사용자</li><li>마지막 로그인: 2026-09-09</li></ul></body></html>`;

const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://x");
  const p = u.pathname;
  const authed = (req.headers.cookie ?? "").includes(VICTIM);
  const send = (code, body, headers = {}) => {
    for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
    res.statusCode = code;
    res.end(body);
  };

  if (p === "/") {
    return send(200, `<html><body><h1>쇼핑몰</h1><a href="/profile">마이페이지</a> <a href="/login">로그인</a></body></html>`);
  }
  if (p === "/login") {
    // 데모 로그인: 세션 쿠키 발급(테스트 편의).
    return send(200, `<html><body>logged in</body></html>`, { "Set-Cookie": `${VICTIM}; Path=/` });
  }
  if (p === "/profile") {
    if (!authed) return send(302, `<html><body>redirect login</body></html>`, { Location: "/login" });
    return send(200, PAGE("lee", "lee@example.com"), { "Cache-Control": "private, no-store" });
  }
  // 정적 확장자 접미사 경로 — 취약 서버: 접미사 무시 + 개인 페이지 + 공개 캐시 가능.
  if (/^\/profile\/[^/]+\.(css|js|png)$/.test(p)) {
    return send(200, PAGE("lee", "lee@example.com"), { "Cache-Control": "public, max-age=60", "X-Cache": authed ? "MISS" : "HIT" });
  }
  return send(404, "nf");
});

server.listen(port, "127.0.0.1", () => console.log("vuln-cache-deception lab on", port));
