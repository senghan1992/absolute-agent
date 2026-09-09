// UNION-capable vulnerable lab (MySQL emulation) — P0.5 e2e target
const http = require("http");
const port = Number(process.env.PORT ?? 18089);
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  const p = url.pathname;
  const send = (code, body, ct = "text/html; charset=utf-8") => {
    res.writeHead(code, { "Content-Type": ct });
    res.end(body);
  };
  if (p === "/.env") {
    return send(200, "DB_HOST=127.0.0.1\nDB_USER=admin\nDB_PASSWORD=s3cr3t-passw0rd!x\nJWT_SECRET=dev-jwt-secret-0123456789abcdef\n", "text/plain");
  }
  if (p === "/users/1" || p === "/users/2") {
    const u = p === "/users/1" ? { id: 1, name: "김철수", email: "kim@corp.local", phone: "010-1234-5678" } : { id: 2, name: "이영희", email: "lee@corp.local", phone: "010-9876-5432" };
    return send(200, JSON.stringify(u), "application/json");
  }
  if (p === "/admin") return send(200, "<html><body>admin panel</body></html>");
  if (p === "/backup.zip") return send(200, "PK\u0003\u0004fake-zip-bytes", "application/zip");
  if (p === "/graphql" && req.method === "POST") {
    return send(200, JSON.stringify({ data: { __schema: { types: [{ name: "Query" }, { name: "User" }] } } }), "application/json");
  }
  if (p === "/search") {
    const q = url.searchParams.get("q") ?? "";
    if (q.includes("R3DX9")) {
      // 취약 앱이 UNION 행(마커|버전)을 그대로 렌더링한다
      return send(200, `<html><body><h1>검색 결과</h1><table><tr><td>R3DX9</td><td>8.0.40-abc</td></tr></table></body></html>`);
    }
    if (q.includes("'")) {
      return send(500, "SQLSTATE[42000]: You have an error in your SQL syntax near '' at line 1 (MySQL server 8.0.40)");
    }
    return send(200, `<html><body><h1>검색 결과</h1><p>none</p></body></html>`);
  }
  if (p === "/") return send(200, "<html><body><a href=\"/search\">검색</a> <a href=\"/users/1\">u1</a></body></html>");
  return send(404, "nf");
});
server.listen(port, "127.0.0.1", () => console.log("vuln-union lab on", port));
