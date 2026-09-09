// Reflected XSS lab — q 파라미터를 이스케이프 없이 HTML 문맥에 반사한다
const http = require("http");
const port = Number(process.env.PORT ?? 18093);
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  const p = url.pathname;
  const send = (code, body, ct = "text/html; charset=utf-8") => {
    res.writeHead(code, { "Content-Type": ct });
    res.end(body);
  };
  if (p === "/") {
    const q = url.searchParams.get("q");
    if (q !== null) {
      // 취약 앱: 사용자 입력을 HTML 이스케이프 없이 <mark> 안에 그대로 출력
      return send(200, `<!doctype html><html><body><h1>검색 결과</h1><p><mark>${q}</mark></p></body></html>`);
    }
    return send(200, '<html><body><h1>검색</h1><a href="/?q=hello">검색하기</a></body></html>');
  }
  return send(404, "nf");
});
server.listen(port, "127.0.0.1", () => console.log("vuln-xss lab on", port));
