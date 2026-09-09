// Credential-reuse chain lab (P2) — NO other vulns. Login form at "/".
//   /.env leaks ADMIN_USER/ADMIN_PASSWORD → chain reuses them at /login → /admin.
const http = require("http");
const port = Number(process.env.PORT ?? 18092);
const ADMIN_USER = "admin";
const ADMIN_PASS = "s3cr3t-lab-77";

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://x:${port}`);
  const p = url.pathname;
  if (p === "/.env") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("ADMIN_USER=" + ADMIN_USER + "\nADMIN_PASSWORD=" + ADMIN_PASS + "\nDB_HOST=127.0.0.1\nAPP_PORT=18092\n");
  }
  if (p === "/") {
    res.writeHead(200, { "Content-Type": "text/html" });
    return res.end(
      "<html><head><title>관리자 로그인</title></head><body>" +
        '<h1>관리자 로그인</h1><form action="/login" method="post">' +
        '<input name="username" type="text" placeholder="아이디"><input name="password" type="password" placeholder="비밀번호">' +
        '<button type="submit">로그인</button></form></body></html>',
    );
  }
  if (p === "/login" && req.method === "POST") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const params = new URLSearchParams(body);
      if (params.get("username") === ADMIN_USER && params.get("password") === ADMIN_PASS) {
        res.writeHead(302, { Location: "/admin", "Set-Cookie": "session=valid-abc; Path=/" });
        return res.end();
      }
      res.writeHead(200, { "Content-Type": "text/html" });
      return res.end('<html><body><p>로그인 실패</p></body></html>');
    });
    return;
  }
  if (p === "/admin") {
    const cookie = req.headers.cookie ?? "";
    if (cookie.includes("session=valid-abc")) {
      res.writeHead(200, { "Content-Type": "text/html" });
      return res.end("<html><body><h1>관리자 대시보드</h1><p>플래그: FLAG-CHAIN-OK-42</p></body></html>");
    }
    res.writeHead(302, { Location: "/login" });
    return res.end();
  }
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("not found");
});

server.listen(port, "127.0.0.1", () => {
  process.stdout.write(`vuln-creds lab on http://127.0.0.1:${port}\n`);
});
