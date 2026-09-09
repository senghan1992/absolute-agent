/**
 * vuln-smuggle — HTTP Request Smuggling 랩.
 *
 * raw TCP 서버로 **CL-우선 파서**(구형 프록시가 흔히 그렇듯 Content-Length 를 따르고
 * Transfer-Encoding 을 무시)를 구현한다. 중복 CL 은 "가장 큰 값"을 선택한다(파서 불일치
 * 시뮬레이션). RFC 준수 서버(Node http)와 달리 CL+TE 충돌을 거부하지 않는다 →
 * smuggle_probe 의 스톨 차등이 관측된다(스머글링 실증).
 *
 * 안전: 학습/검증용 로컬 랩이다. 실제 밀반입은 수행하지 않는다.
 */
const net = require("node:net");
const port = Number(process.env.PORT ?? 18113);

/** 요청 1개 파싱 — CL 우선(취약): CL 이 있으면 TE 를 무시한다. 중복 CL 은 최대값 선택. */
function tryParse(buf) {
  const end = buf.indexOf("\r\n\r\n");
  if (end < 0) return { complete: false, consume: 0 };
  const head = buf.slice(0, end);
  const cls = [...head.matchAll(/content-length:\s*(\d+)/gi)].map((m) => Number(m[1]));
  const hasTe = /transfer-encoding:/i.test(head);
  if (cls.length === 0 && !hasTe) {
    // GET 등 본문 없는 요청.
    return { complete: true, consume: end + 4, path: head.split("\r\n")[0].split(" ")[1] };
  }
  if (cls.length === 0) return { complete: false, consume: 0 }; // TE-전용 요청도 대기(파서 불일치의 일부)
  const cl = Math.max(...cls);
  const total = end + 4 + cl;
  if (buf.length < total) return { complete: false, consume: 0 };
  return { complete: true, consume: total, path: head.split("\r\n")[0].split(" ")[1] };
}

const server = net.createServer((sock) => {
  let buf = "";
  sock.on("data", (d) => {
    buf += d.toString("latin1");
    for (;;) {
      const r = tryParse(buf);
      if (!r.complete) break; // 남은 바이트를 기다린다(= 스톨의 원인)
      buf = buf.slice(r.consume);
      const body = `ok path=${r.path}`;
      sock.write(`HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`);
      sock.end();
      return;
    }
  });
  sock.on("error", () => {});
});

server.listen(port, "127.0.0.1", () => console.log("vuln-smuggle lab on", port));
