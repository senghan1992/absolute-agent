/**
 * panel — RedCell 실시간 데스크톱 패널(로컬 전용, 의존성 0).
 *
 * RLM 에이전트/엔게이지먼트의 OrchestratorEvent 스트림을 로컬 HTTP + SSE 로
 * 서빙하는 셀프컨테인드 HTML 패널이다. 외부 CDN/네트워크를 전혀 사용하지 않으므로
 * 오프라인 환경에서도 동작한다(127.0.0.1 바인딩).
 *
 *   start() → LivePanel  (GET / : 패널 HTML, GET /events : SSE)
 *   panel.push(event)    (OrchestratorEvent JSON 을 모든 클라이언트에 브로드캐스트)
 *   panel.close()        (서버 종료)
 *
 * 패널 화면: 이벤트 타임라인(recall/action/reward/distilled/reflect/verify/finding) +
 * 통계 카드(액션·발견·누적 보상·회상·증류·반성·검증) + 누적 보상 스파크라인.
 */
import http from "node:http";
import type { AddressInfo } from "node:net";
import type { OrchestratorEvent } from "../core/orchestrator.js";

export interface LivePanelOpts {
  /** 패널 제목(대상/모드 표시). 기본 "RedCell Live". */
  title?: string;
  /** SSE 히스토리 유지 개수(새로 연결된 브라우저에 재생). 기본 500. */
  history?: number;
}

const PAGE = String.raw`<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<title>RedCell Live Panel</title>
<style>
  :root {
    --bg:#0b0e14; --panel:#121722; --line:#232b3d; --txt:#d7e0f0; --dim:#7b879c;
    --green:#3ddc84; --red:#ff5d6c; --yellow:#ffd166; --cyan:#36c5f0; --magenta:#c792ea;
    --blue:#4f9cf9; --gray:#9aa7bd;
  }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--txt); font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; padding:18px; }
  header { display:flex; align-items:baseline; gap:12px; margin-bottom:14px; flex-wrap:wrap; }
  h1 { font-size:16px; letter-spacing:.5px; color:var(--green); font-weight:700; }
  .dot { width:9px; height:9px; border-radius:50%; background:var(--dim); display:inline-block; }
  .dot.on { background:var(--green); box-shadow:0 0 8px var(--green); animation:pulse 1.6s infinite; }
  @keyframes pulse { 50% { opacity:.45; } }
  .sub { color:var(--dim); font-size:12px; }
  #title { color:var(--cyan); }
  #status { color:var(--dim); }
  main { display:grid; grid-template-columns: 300px 1fr; gap:14px; }
  @media (max-width:900px) { main { grid-template-columns: 1fr; } }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:12px; }
  #stats h2, #events h2 { font-size:11px; color:var(--dim); text-transform:uppercase; letter-spacing:1px; margin-bottom:10px; }
  .stat { display:flex; justify-content:space-between; padding:5px 2px; border-bottom:1px dashed #1c2436; }
  .stat:last-child { border-bottom:none; }
  .stat b { color:var(--yellow); }
  .badge { display:inline-block; padding:1px 7px; border-radius:20px; font-size:11px; border:1px solid var(--line); color:var(--txt); }
  #verify.achieved { color:var(--green); border-color:var(--green); }
  #verify.partial { color:var(--yellow); border-color:var(--yellow); }
  #verify.unclear { color:var(--red); border-color:var(--red); }
  #spark { width:100%; height:70px; margin-top:8px; }
  #events { height:min(72vh,640px); overflow-y:auto; }
  .ev { padding:6px 8px; border-left:3px solid var(--gray); margin-bottom:4px; border-radius:0 6px 6px 0; background:#0e1320; }
  .ev .t { color:var(--dim); font-size:11px; margin-right:8px; }
  .ev .tx { white-space:pre-wrap; word-break:break-all; }
  .ev.recall { border-color:var(--cyan); } .ev.recall .t { color:var(--cyan); }
  .ev.action { border-color:var(--green); } .ev.action .t { color:var(--green); }
  .ev.reward { border-color:var(--yellow); } .ev.reward .t { color:var(--yellow); }
  .ev.distilled { border-color:var(--magenta); } .ev.distilled .t { color:var(--magenta); }
  .ev.reflect { border-color:var(--magenta); } .ev.reflect .t { color:var(--magenta); }
  .ev.verify { border-color:var(--blue); } .ev.verify .t { color:var(--blue); }
  .ev.finding { border-color:var(--red); } .ev.finding .t { color:var(--red); }
  .ev.error { border-color:var(--red); } .ev.error .t { color:var(--red); font-weight:700; }
  .ev.done { border-color:var(--green); } .ev.done .t { color:var(--green); font-weight:700; }
  .ev.tool_result, .ev.note { border-color:var(--gray); }
</style>
</head>
<body>
<header>
  <h1>REDCELL <span class="dot" id="dot"></span></h1>
  <span class="sub">live panel</span>
  <span class="sub" id="title"></span>
  <span id="status"></span>
</header>
<main>
  <section class="card" id="stats">
    <h2>학습 상태</h2>
    <div class="stat"><span>액션 스텝</span><b id="st-actions">0</b></div>
    <div class="stat"><span>발견</span><b id="st-findings">0</b></div>
    <div class="stat"><span>누적 보상</span><b id="st-reward">0.00</b></div>
    <div class="stat"><span>회상(recall)</span><b id="st-recall">0</b></div>
    <div class="stat"><span>증류(distill)</span><b id="st-distilled">0</b></div>
    <div class="stat"><span>반성(reflect)</span><b id="st-reflect">0</b></div>
    <div class="stat"><span>검증(verify)</span><span class="badge" id="verify">-</span></div>
    <canvas id="spark" width="276" height="70"></canvas>
  </section>
  <section class="card" id="events">
    <h2>이벤트 타임라인</h2>
    <div id="tl"></div>
  </section>
</main>
<script>
const $ = (id) => document.getElementById(id);
const esc = (s) => (s ?? "").replace(/[&<>"]/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const es = new EventSource("/events");
const state = { reward: [], actions: 0, findings: 0, recall: 0, distilled: 0, reflect: 0 };
es.onopen = () => { $("dot").classList.add("on"); $("status").textContent = "connected"; };
es.onerror = () => { $("dot").classList.remove("on"); $("status").textContent = "disconnected"; };
es.onmessage = (msg) => {
  const e = JSON.parse(msg.data);
  if (e.type === "meta") { $("title").textContent = e.title ?? ""; return; }
  const row = document.createElement("div");
  row.className = "ev " + e.type;
  const t = new Date().toLocaleTimeString();
  row.innerHTML = '<span class="t">[' + esc(e.type) + " " + t + "]</span><span class='tx'>" + esc(e.text) + "</span>";
  $("tl").prepend(row);
  while ($("tl").children.length > 400) $("tl").lastChild.remove();
  if (e.type === "action") { state.actions++; $("st-actions").textContent = state.actions; }
  if (e.type === "finding") { state.findings++; $("st-findings").textContent = state.findings; }
  if (e.type === "reward") {
    state.reward.push(e.value);
    $("st-reward").textContent = state.reward.reduce((a, b) => a + b, 0).toFixed(2);
    drawSpark();
  }
  if (e.type === "recall") { state.recall = e.count; $("st-recall").textContent = e.count; }
  if (e.type === "distilled") { state.distilled++; $("st-distilled").textContent = state.distilled; }
  if (e.type === "reflect") { state.reflect++; $("st-reflect").textContent = state.reflect; }
  if (e.type === "verify") {
    const v = $("verify");
    v.textContent = e.verdict + " (" + Math.round(e.ratio * 100) + "%)";
    v.className = "badge " + e.verdict;
  }
};
function drawSpark() {
  const c = $("spark"), ctx = c.getContext("2d"), dpr = window.devicePixelRatio || 1;
  c.width = c.clientWidth * dpr; c.height = c.clientHeight * dpr;
  ctx.scale(dpr, dpr); ctx.clearRect(0, 0, c.clientWidth, c.clientHeight);
  const pts = state.reward.slice(-200), w = c.clientWidth, h = c.clientHeight;
  if (pts.length < 2) return;
  const max = Math.max(...pts, 0.01), min = Math.min(...pts, 0);
  ctx.strokeStyle = "#ffd166"; ctx.lineWidth = 1.6; ctx.beginPath();
  pts.forEach((v, i) => {
    const x = (i / (pts.length - 1)) * w, y = h - ((v - min) / (max - min || 1)) * (h - 6) - 3;
    i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
  });
  ctx.stroke();
}
window.addEventListener("resize", drawSpark);
</script>
</body>
</html>`;

export class LivePanel {
  readonly port: number;
  private server: http.Server;
  private clients = new Set<http.ServerResponse>();
  private history: unknown[] = [];

  private constructor(server: http.Server, port: number) {
    this.server = server;
    this.port = port;
  }

  static start(opts: LivePanelOpts = {}, port = 5173): Promise<LivePanel> {
    const title = opts.title ?? "RedCell Live";
    const cap = opts.history ?? 500;
    const server = http.createServer((req, res) => {
      const url = req.url ?? "/";
      if (url === "/events") {
        res.writeHead(200, {
          "content-type": "text/event-stream",
          "cache-control": "no-cache",
          connection: "keep-alive",
        });
        res.write("retry: 1500\n\n");
        // 새 구독자에게 메타 + 지금까지의 이벤트를 재생한다.
        res.write(`data: ${JSON.stringify({ type: "meta", title })}\n\n`);
        for (const ev of thisRef(server).history) res.write(`data: ${JSON.stringify(ev)}\n\n`);
        thisRef(server).clients.add(res);
        req.on("close", () => thisRef(server).clients.delete(res));
        return;
      }
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(PAGE);
    });
    // thisRef: 클로저에서 self 참조를 안전하게 유지.
    function thisRef(s: http.Server): LivePanel {
      return (s as unknown as { panel: LivePanel }).panel;
    }
    return new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, "127.0.0.1", () => {
        server.removeListener("error", reject);
        const addr = server.address() as AddressInfo;
        const panel = new LivePanel(server, addr.port);
        (server as unknown as { panel: LivePanel }).panel = panel;
        resolve(panel);
      });
    });
  }

  /** OrchestratorEvent 또는 meta JSON 을 모든 구독자에게 브로드캐스트. */
  push(e: unknown): void {
    this.history.push(e);
    const cap = 500;
    if (this.history.length > cap) this.history.splice(0, this.history.length - cap);
    const data = `data: ${JSON.stringify(e)}\n\n`;
    for (const res of this.clients) res.write(data);
  }

  close(): Promise<void> {
    for (const res of this.clients) res.end();
    this.clients.clear();
    return new Promise((resolve) => this.server.close(() => resolve()));
  }
}
