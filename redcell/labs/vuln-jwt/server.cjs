/**
 * vuln-jwt — JWT 위조 실증 랩.
 *
 *   - HS256 서명에 **약한 시크릿("secret")** 사용 → 사전 크랙 후 role=admin 재서명 가능.
 *   - 토큰 검증이 **alg=none 을 수용**(서명 검증 생략) → 서명 없는 위조 토큰도 통과.
 *   - /api/me 가 토큰의 role 을 응답에 그대로 반영 → 특권 승격 신호 관측 가능.
 *
 * 학습/검증용 로컬 랩이다. 강한 시크릿 + none 거부가 정상 구현이다(대조군은 테스트).
 */
const http = require("node:http");
const crypto = require("node:crypto");
const port = Number(process.env.PORT ?? 18115);
const SECRET = process.env.JWT_SECRET ?? "secret"; // 취약: 약한 시크릿

const b64u = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const hs256 = (hp, secret) => crypto.createHmac("sha256", secret).update(hp).digest("base64url");
const sign = (payload) => {
  const hp = `${b64u({ typ: "JWT", alg: "HS256" })}.${b64u(payload)}`;
  return `${hp}.${hs256(hp, SECRET)}`;
};

/** 취약 검증: alg=none 수용(서명 검증 생략) + 약한 HMAC. */
function verify(tok) {
  const parts = String(tok).split(".");
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    if (header.alg === "none") return payload; // 취약: none 수용
    const expected = hs256(`${parts[0]}.${parts[1]}`, SECRET);
    if (expected === parts[2]) return payload;
    return null;
  } catch {
    return null;
  }
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://x");
  const send = (code, body, headers = {}) => {
    for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
    res.statusCode = code;
    res.end(body);
  };
  const bearer = (req.headers.authorization ?? "").replace(/^Bearer\s+/i, "");

  if (u.pathname === "/") {
    return send(200, `<html><body><h1>JWT 데모 앱</h1><a href="/login?user=admin">로그인</a> <a href="/api/me">내 정보</a></body></html>`);
  }
  if (u.pathname === "/login") {
    const user = u.searchParams.get("user") || "guest";
    const tok = sign({ user, role: "user", iat: 1700000000, exp: 1900000000 });
    return send(200, `{"token":"${tok}"}`, { "Set-Cookie": `access_token=${tok}; Path=/` });
  }
  if (u.pathname === "/api/me") {
    const payload = verify(bearer);
    if (!payload) return send(401, `{"error":"unauthorized","detail":"signature invalid"}`);
    return send(200, `{"user":"${payload.user}","role":"${payload.role}","isAdmin":${payload.role === "admin"}}`);
  }
  return send(404, "nf");
});

server.listen(port, "127.0.0.1", () => console.log("vuln-jwt lab on", port));
