// Clean lab: echo service with no known vuln — negative control for FP
const http = require("http");
const port = Number(process.env.PORT ?? 18091);
const server = http.createServer((req, res) => {
  res.setHeader("Content-Security-Policy", "default-src 'self'");
  res.setHeader("Strict-Transport-Security", "max-age=31536000");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  const url = new URL(req.url, "http://x");
  if (url.pathname === "/") return res.end("<html><body><h1>echo service</h1></body></html>");
  if (url.pathname === "/echo") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("echo: " + (url.searchParams.get("msg") ?? ""));
  }
  res.writeHead(404); res.end("nf");
});
server.listen(port, "127.0.0.1", () => console.log("clean-shop lab on", port));
