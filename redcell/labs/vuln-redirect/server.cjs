// Open redirect lab — next 파라미터 값을 검증 없이 302 Location 으로 쓴다
const http = require("http");
const port = Number(process.env.PORT ?? 18097);
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  const p = url.pathname;
  if (p === "/") {
    const next = url.searchParams.get("next");
    if (next !== null) {
      res.writeHead(302, { "Location": next });
      return res.end();
    }
    const body = '<html><body><h1>리다이렉트</h1><a href="/?next=http://example.com/">이동하기</a></body></html>';
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    return res.end(body);
  }
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("nf");
});
server.listen(port, "127.0.0.1", () => console.log("vuln-redirect lab on", port));
