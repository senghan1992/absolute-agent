// LFI lab — file 파라미터를 경로 검증 없이 읽어 /etc/passwd 를 그대로 노출한다
const http = require("http");
const port = Number(process.env.PORT ?? 18096);
const PASSWD = "root:x:0:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin";
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  const p = url.pathname;
  const send = (code, body, ct = "text/html; charset=utf-8") => {
    res.writeHead(code, { "Content-Type": ct });
    res.end(body);
  };
  if (p === "/") {
    const fileParam = url.searchParams.get("file");
    if (fileParam !== null) {
      let file = fileParam;
      // 취약 앱: 인코딩을 한 번 더 디코드한 뒤 아무 검증 없이 파일을 읽어 반환
      try { file = decodeURIComponent(file); } catch { /* 원문 유지 */ }
      file = file.replace(/^.*?etc\/passwd/, "etc/passwd").replace(/^etc\/passwd/, "/etc/passwd");
      if (file === "/etc/passwd" || file.includes("/etc/passwd")) {
        return send(200, PASSWD, "text/plain");
      }
      return send(200, "<!doctype html><html><body><p>문서를 찾을 수 없습니다</p></body></html>");
    }
    return send(200, '<html><body><h1>문서 열람</h1><a href="/?file=README">문서 보기</a></body></html>');
  }
  return send(404, "nf");
});
server.listen(port, "127.0.0.1", () => console.log("vuln-lfi lab on", port));
