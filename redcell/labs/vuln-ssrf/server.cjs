// SSRF lab — url 파라미터를 서버가 대신 요청하는 "프록시"가, 클라우드 메타데이터 응답을 그대로 반사한다
const http = require("http");
const port = Number(process.env.PORT ?? 18095);
const META = JSON.stringify({
  ami_id: "ami-0abc123def456",
  instance_id: "i-0f9e8d7c6b5a4321",
  "iam/security-credentials/role": {
    AccessKeyId: "AKIAEXAMPLE1234567890",
    SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    Token: "FwoGZXIvYXdzEXXX",
    Expiration: "2025-12-31T00:00:00Z"
  }
}, null, 2);
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  const p = url.pathname;
  const send = (code, body, ct = "text/html; charset=utf-8") => {
    res.writeHead(code, { "Content-Type": ct });
    res.end(body);
  };
  if (p === "/") {
    const u = url.searchParams.get("url");
    if (u !== null) {
      // 취약 앱: 공격자가 준 URL 을 서버가 fetch 해 그 응답을 그대로 돌려준다
      return send(200, META, "application/json");
    }
    return send(200, '<html><body><h1>URL 프록시</h1><a href="/?url=http://example.com/">요청해보기</a></body></html>');
  }
  return send(404, "nf");
});
server.listen(port, "127.0.0.1", () => console.log("vuln-ssrf lab on", port));
