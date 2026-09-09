// IDOR-only vulnerable lab (no other vulns) — P1 lab-bench fixture
const http = require("http");
const port = Number(process.env.PORT ?? 18090);
const users = {
  1: { id: 1, name: "김철수", email: "kim@corp.local", phone: "010-1234-5678" },
  2: { id: 2, name: "이영희", email: "lee@corp.local", phone: "010-9876-5432" },
  3: { id: 3, name: "박민지", email: "park@corp.local", phone: "010-5555-9999" },
};
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  const m = url.pathname.match(/^\/users\/([0-9]+)$/);
  if (m) {
    const u = users[m[1]];
    if (!u) { res.writeHead(404); return res.end("nf"); }
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify(u));
  }
  if (url.pathname === "/") return res.end("<html><body><a href=\"/users/1\">u1</a> <a href=\"/users/2\">u2</a></body></html>");
  res.writeHead(404); res.end("nf");
});
server.listen(port, "127.0.0.1", () => console.log("vuln-idor lab on", port));
