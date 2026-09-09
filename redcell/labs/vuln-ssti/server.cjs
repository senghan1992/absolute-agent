// SSTI lab — name 파라미터의 산술식만 서버측에서 평가해 결과를 렌더한다(원문 미에코)
const http = require("http");
const port = Number(process.env.PORT ?? 18094);
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  const p = url.pathname;
  const send = (code, body, ct = "text/html; charset=utf-8") => {
    res.writeHead(code, { "Content-Type": ct });
    res.end(body);
  };
  if (p === "/") {
    const name = url.searchParams.get("name") ?? "";
    // 템플릿 엔진이 "문자열 안의 곱셈식"을 평가해 렌더한다({{..}} 등 래퍼 무관)
    const m = /(\d+)\*(\d+)/.exec(name);
    if (m) return send(200, `<!doctype html><html><body><p>렌더 결과: ${parseInt(m[1], 10) * parseInt(m[2], 10)}</p></body></html>`);
    if (name) return send(200, "<!doctype html><html><body><p>안녕하세요</p></body></html>");
    return send(200, '<html><body><h1>인사</h1><a href="/?name=guest">인사하기</a></body></html>');
  }
  return send(404, "nf");
});
server.listen(port, "127.0.0.1", () => console.log("vuln-ssti lab on", port));
