// XXE lab — POST XML 본문의 내부 엔티티를 확장해 응답에 반사한다 (외부 엔티티 도달은 차단)
const http = require("http");
const port = Number(process.env.PORT ?? 18098);
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  const p = url.pathname;
  const send = (code, body, ct = "text/html; charset=utf-8") => {
    res.writeHead(code, { "Content-Type": ct });
    res.end(body);
  };
  if (req.method === "POST") {
    let raw = "";
    req.on("data", (c) => { raw += c; });
    req.on("end", () => {
      // 취약 XML 파서: 내부 엔티티 선언을 확장해 엘리먼트 값으로 렌더링
      const m = /<!ENTITY\s+xxe\s+"([^"]+)"/.exec(raw);
      if (m) return send(200, `<?xml version="1.0"?><import><status>ok</status><value>${m[1]}</value></import>`, "application/xml");
      return send(400, "<error>bad xml</error>", "application/xml");
    });
    return;
  }
  if (p === "/") {
    return send(200, '<html><body><h1>XML 가져오기</h1><form method="post" action="/api/import"><textarea name="xml"></textarea><button type="submit">전송</button></form></body></html>');
  }
  return send(404, "nf");
});
server.listen(port, "127.0.0.1", () => console.log("vuln-xxe lab on", port));
