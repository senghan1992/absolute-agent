// RedCell — operator console 프론트엔드.
// 왼쪽 메인 패널 = Wireshark 스타일 라이브 캡처(이벤트 테이블 + 상세).
// 오른쪽 = 에이전트 지시 패널. 백엔드(Tauri)와 invoke/event 로 통신.

const TAURI = window.__TAURI__;
const invoke = TAURI ? TAURI.core.invoke : async () => { throw new Error("Tauri 환경이 아닙니다"); };
const listen = TAURI ? TAURI.event.listen : async () => {};

let sessions = [];
let activeId = null;
let settings = { redcell_dir: "", auth_path: "", default_provider: "" };
let selectedSeq = null;

const PHASE_ORDER = ["recon", "enumerate", "exploit", "post"];

const $ = (id) => document.getElementById(id);
const cur = () => sessions.find((s) => s.id === activeId) || null;
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const clock = (ms) => { try { return new Date(ms).toLocaleTimeString("en-GB", { hour12: false }); } catch { return ""; } };
const hhmm = (ts) => { try { return new Date(ts).toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit" }); } catch { return ""; } };

const eventsOf = (s) => (s && s.events) || [];
function doneLog(s) { const d = [...eventsOf(s)].reverse().find((e) => e.type === "done"); return d ? d.log : null; }
function findingsOf(s) {
  const dl = doneLog(s);
  if (dl && dl.findings) return dl.findings;
  return eventsOf(s).filter((e) => e.type === "finding").map((e) => e.finding);
}
function fingerprintOf(s) { const dl = doneLog(s); return (dl && dl.fingerprint) || {}; }
function playbooksOf(s) {
  const dl = doneLog(s);
  return { used: (dl && dl.usedPlaybooks) || [], distilled: ((dl && dl.distilled) || []).map((p) => p.title || p.id) };
}

// ── 이벤트 → 캡처 행 필드 ────────────────────────────────────────────────────
function rowFields(e, i) {
  const seq = e._seq != null ? e._seq : i;
  const time = e._ts ? clock(e._ts) : "";
  const phase = e.phase || "—";
  const tool = e.tool || (e.type === "finding" && e.finding ? e.finding.phase : "") || "—";
  const msg = e.text || (e.finding ? e.finding.title : "") || JSON.stringify(e);
  let status = "";
  if (e.type === "finding") status = e.finding ? e.finding.severity : "info";
  else if (e.type === "tool_result") status = e.ok ? "ok" : "fail";
  else if (e.type === "blocked") status = "blocked";
  else if (e.type === "error") status = "error";
  else if (e.type === "authorized" || e.type === "done") status = "ok";
  return { seq, time, phase, tool, msg, status, type: e.type || "note", sev: e.finding ? e.finding.severity : (e.severity || "") };
}
function rowHtml(e, i) {
  const f = rowFields(e, i);
  const cls = ["row-" + f.type];
  if (f.type === "finding") cls.push("sev-" + (f.sev || "info"));
  const stTxt = f.status ? `<span class="st ${f.status}">${f.status}</span>` : "";
  return `<tr class="${cls.join(" ")}${f.seq === selectedSeq ? " sel" : ""}" data-seq="${f.seq}">
    <td class="c-seq">${f.seq}</td>
    <td class="c-time">${f.time}</td>
    <td class="c-phase">${esc(f.phase)}</td>
    <td class="c-tool">${esc(f.tool)}</td>
    <td class="c-msg">${esc(f.msg)}</td>
    <td class="c-status">${stTxt}</td>
  </tr>`;
}

// ── 렌더: 세션 탭 ────────────────────────────────────────────────────────────
function renderTabs() {
  const nav = $("tabs");
  nav.innerHTML = "";
  for (const s of sessions) {
    const tab = document.createElement("div");
    tab.className = "tab" + (s.id === activeId ? " active" : "");
    tab.innerHTML = `<span class="tdot ${s.status}"></span><span class="tname">${esc(s.name)}</span><span class="tclose" title="세션 닫기"><svg class="ic"><use href="#i-x"/></svg></span>`;
    tab.querySelector(".tname").onclick = () => selectSession(s.id);
    tab.querySelector(".tdot").onclick = () => selectSession(s.id);
    tab.querySelector(".tclose").onclick = (e) => { e.stopPropagation(); removeSession(s.id); };
    nav.appendChild(tab);
  }
}

// ── 렌더: 활성 세션 전체 ─────────────────────────────────────────────────────
function renderActive() {
  const s = cur();
  const empty = $("emptyState");
  if (!s) { empty.classList.remove("hidden"); return; }
  empty.classList.add("hidden");
  selectedSeq = null;

  $("shName").value = s.name || "";
  $("shHost").value = s.host || "";
  $("shPort").value = s.port ?? "";
  $("shGoal") && ($("shGoal").value = s.goal || "");
  $("shProvider").value = s.provider && s.provider !== "mock" ? s.provider : "";
  $("shMode") && ($("shMode").value = s.mode || "tools");
  setBadge(s.status);

  renderCapture(s);
  renderStepper(s);
  renderMetrics(s);
  renderFindings(s);
  renderIntel(s);
  renderNext(s);
  renderChat();
  renderDetail(null);
}

function setBadge(status) {
  const b = $("statusBadge");
  b.textContent = status;
  b.className = "badge badge-" + status;
  const running = status === "running";
  const btn = $("runBtn");
  btn.disabled = false;
  btn.dataset.mode = running ? "stop" : "run";
  btn.classList.toggle("btn-run", !running);
  btn.classList.toggle("btn-stop", running);
  btn.title = running ? "실행 중지" : "현재 목표로 엔진 실행";
  $("runIcon").innerHTML = '<use href="#' + (running ? "i-stop" : "i-play") + '"/>';
  $("runLabel").textContent = running ? "중지" : status === "idle" ? "실행" : "재실행";
  const state = $("agentState");
  state.textContent = running ? "작동 중" : (status === "done" ? "완료" : status === "error" ? "오류" : status === "stopped" ? "중지됨" : "대기");
  state.className = "agent-state" + (running ? " busy" : "");
  if (running) setActivity($("activityText").textContent || "에이전트가 계획을 세우는 중…");
  else hideActivity();
}

// ── 캡처 테이블 ──────────────────────────────────────────────────────────────
function renderCapture(s) {
  const body = $("capBody");
  const evs = eventsOf(s);
  body.innerHTML = evs.map((e, i) => rowHtml(e, i)).join("");
  $("capEmpty").style.display = evs.length ? "none" : "block";
  wireRows();
  const cap = document.querySelector(".capture");
  if (cap) cap.scrollTop = cap.scrollHeight;
}
function wireRows() {
  document.querySelectorAll("#capBody tr").forEach((tr) => {
    tr.onclick = () => {
      selectedSeq = parseInt(tr.dataset.seq, 10);
      document.querySelectorAll("#capBody tr").forEach((x) => x.classList.remove("sel"));
      tr.classList.add("sel");
      const s = cur();
      const ev = eventsOf(s).find((e) => (e._seq != null ? e._seq : -1) === selectedSeq) || eventsOf(s)[selectedSeq];
      renderDetail(ev);
    };
  });
}

function renderStepper(s) {
  const evs = eventsOf(s);
  const seen = new Set(evs.filter((e) => e.type === "phase").map((e) => e.phase));
  const lastPhase = [...evs].reverse().find((e) => e.type === "phase");
  const running = s.status === "running";
  const finished = evs.some((e) => e.type === "done") || s.status === "done" || s.status === "error";
  PHASE_ORDER.forEach((p, i) => {
    const el = document.querySelector(`.step[data-phase="${p}"]`);
    if (!el) return;
    const reached = seen.has(p);
    const isCurrent = lastPhase && lastPhase.phase === p;
    const passed = lastPhase && PHASE_ORDER.indexOf(lastPhase.phase) > i;
    el.classList.toggle("active", running && !finished && isCurrent);
    el.classList.toggle("done", reached && (finished || passed));
  });
}

function renderMetrics(s) {
  const evs = eventsOf(s);
  const fs = findingsOf(s);
  const c = { critical: 0, high: 0, medium: 0, low: 0 };
  fs.forEach((f) => { if (c[f.severity] != null) c[f.severity]++; });
  $("mEvents").textContent = evs.length;
  $("mCrit").textContent = c.critical;
  $("mHigh").textContent = c.high;
  $("mMed").textContent = c.medium;
  $("mLow").textContent = c.low;
  $("mBlocked").textContent = evs.filter((e) => e.type === "blocked").length;
  $("cntFindings").textContent = fs.length;
}

// ── 상세 드릴다운 ────────────────────────────────────────────────────────────
function renderDetail(ev) {
  const el = $("detail");
  if (!ev) { el.innerHTML = `<div class="detail-empty">행을 선택하면 상세가 표시됩니다.</div>`; return; }
  const row = (k, v) => `<div class="d-row"><span class="d-k">${esc(k)}</span><span class="d-v">${esc(v)}</span></div>`;
  let html = `<h4>${esc(ev.type || "event")}</h4>`;
  if (ev.type === "finding" && ev.finding) {
    const f = ev.finding;
    html += row("severity", f.severity) + row("phase", f.phase || "—") + row("title", f.title);
    if (f.detail) html += `<pre>${esc(f.detail)}</pre>`;
    if (f.evidence) html += `<h4 style="margin-top:10px">evidence</h4><pre>${esc(f.evidence)}</pre>`;
  } else if (ev.type === "action") {
    html += row("tool", ev.tool || "—") + row("phase", ev.phase || "—");
    if (ev.rationale) html += row("rationale", ev.rationale);
    // absolute-agent(pyrun): 에이전트가 스스로 작성한 파이썬 코드는 코드블록으로 보여준다.
    if (ev.tool === "python" && ev.args && typeof ev.args.code === "string") {
      html += `<h4 style="margin-top:10px">작성한 파이썬 코드</h4><pre class="code-block"><code>${esc(ev.args.code)}</code></pre>`;
    } else {
      html += `<h4 style="margin-top:10px">args</h4><pre>${esc(JSON.stringify(ev.args ?? {}, null, 2))}</pre>`;
    }
  } else if (ev.type === "tool_result") {
    html += row("tool", ev.tool || "—") + row("phase", ev.phase || "—") + row("ok", String(ev.ok)) + (ev.severity ? row("severity", ev.severity) : "");
    if (ev.summary) html += `<pre>${esc(ev.summary)}</pre>`;
  } else {
    if (ev.phase) html += row("phase", ev.phase);
    html += `<pre>${esc(ev.text || "")}</pre>`;
  }
  html += `<h4 style="margin-top:12px">raw</h4><pre>${esc(JSON.stringify(ev, null, 2))}</pre>`;
  el.innerHTML = html;
}

// ── 발견 ─────────────────────────────────────────────────────────────────────
function renderFindings(s) {
  const el = $("view-findings");
  const fs = findingsOf(s);
  if (!fs.length) { el.innerHTML = `<div class="placeholder">아직 발견된 항목이 없습니다.<br/>오른쪽 에이전트에게 목표를 지시하세요.</div>`; return; }
  el.innerHTML = fs.map((f) => `
    <div class="finding sev-${f.severity}">
      <div class="finding-head">
        <span class="sev-tag ${f.severity}">${f.severity}</span>
        <span class="finding-title">${esc(f.title)}</span>
        <span class="finding-phase">${esc(f.phase || "")}</span>
      </div>
      ${f.detail ? `<div class="finding-detail">${esc(f.detail)}</div>` : ""}
      ${f.evidence ? `<div class="finding-evidence">${esc(f.evidence)}</div>` : ""}
    </div>`).join("");
}

// ── 인텔(핑거프린트 + 학습) ──────────────────────────────────────────────────
function renderIntel(s) {
  const el = $("view-intel");
  const fp = fingerprintOf(s);
  const pb = playbooksOf(s);
  const chips = (arr) => (arr && arr.length ? arr.map((x) => `<span class="chip">${esc(x)}</span>`).join("") : `<span style="color:var(--faint)">—</span>`);
  el.innerHTML = `
    <div class="section-title">타깃 핑거프린트</div>
    <div class="kv">
      <div class="k">service</div><div class="v">${esc(fp.service || "미상")}</div>
      <div class="k">version</div><div class="v">${esc(fp.version || "미상")}</div>
      <div class="k">os</div><div class="v">${esc(fp.os || "미상")}</div>
      <div class="k">tech</div><div class="v">${chips(fp.tech)}</div>
      <div class="k">indicators</div><div class="v">${chips(fp.indicators)}</div>
    </div>
    <div class="section-title">학습(playbook)</div>
    <div class="kv">
      <div class="k">재사용</div><div class="v">${chips(pb.used)}</div>
      <div class="k">새로 학습</div><div class="v">${chips(pb.distilled)}</div>
    </div>`;
}

// ── 다음 단계 (발견 기반 휴리스틱) ──────────────────────────────────────────
function nextSteps(s) {
  const fs = findingsOf(s);
  const blob = fs.map((f) => `${f.title} ${f.detail} ${f.evidence || ""}`).join(" ").toLowerCase();
  const steps = [];
  // 발견 신호 → 구체적 조치 가이드(우선순위 순)
  const RULES = [
    [/sql|sqli/, "SQLi 신호 수동 검증", "탐지된 파라미터를 인가 범위 내에서 오류/부울 기반으로 재현해 영향 범위를 좁히세요. 데이터 추출은 PoC 최소한으로."],
    [/openapi|swagger|api 명세|api-docs/, "API 명세 노출 차단", "/openapi.json·/swagger 등 명세가 외부에 열려 있으면 공격자가 전체 엔드포인트 지도를 얻습니다. 운영 환경에서는 인증 뒤로 옮기거나 비활성화하세요."],
    [/header|헤더|csp|hsts|x-frame/, "보안 헤더 하드닝", "누락된 CSP·HSTS·X-Frame-Options·X-Content-Type-Options·Referrer-Policy 를 추가하고 재스캔으로 검증하세요. (nginx: add_header <헤더> always;)"],
    [/graphql/, "GraphQL 노출 점검", "운영 환경에서 인트로스펙션·플레이그라운드를 비활성화하고 쿼리 깊이/비용 제한을 두세요."],
    [/cors/, "CORS 신뢰 범위 축소", "Access-Control-Allow-Origin 의 와일드카드(*)·과도한 오리진 허용을 제거하고 필요한 도메인만 허용하세요."],
    [/쿠키|cookie/, "세션 쿠키 플래그 설정", "HttpOnly·Secure·SameSite=Lax/Strict 를 설정하세요. 미설정 시 XSS/중간자 공격으로 세션 탈취가 가능합니다."],
    [/jwt/, "JWT 검증 강화", "alg=none 거부·알고리즘 혼동(RS256↔HS256) 방지, 짧은 만료(exp), 페이로드에 민감정보 금지."],
    [/secret|비밀|백업|\.env|credential|키/, "노출 비밀 즉시 폐기", "노출된 키·토큰·설정 파일은 유출로 간주하고 즉시 로테이션한 뒤 접근 로그를 확인하세요."],
    [/upload|업로드/, "업로드 검증 강화", "확장자/MIME 화이트리스트, 저장 경로 실행 권한 제거, 파일명 재생성, 크기 제한."],
    [/login|관리자|admin/, "관리자/로그인 인터페이스 보호", "기본 계정·약한 비밀번호를 점검하고 MFA·로그인 시도 제한(rate limit)·IP 허용목록을 적용하세요."],
    [/열린 포트|port|ssh|redis|postgres|smb|mysql|3306|5432|6379/, "불필요 포트 축소·격리", "DB·캐시(5432/6379/3306) 같은 관리용 포트가 외부에 열려 있으면 방화벽/보안그룹으로 내부 전용으로 격리하세요. SSH 는 키 인증 전용 권장."],
    [/dir|경로|열거|enum/, "노출 경로 점검", "열거된 경로의 접근 통제·디렉터리 인덱싱 여부를 확인하고 불필요한 노출을 차단하세요."],
  ];
  for (const [re, t, d] of RULES) if (re.test(blob)) steps.push([t, d]);
  const fp = fingerprintOf(s);
  if (fp.service && fp.service !== "미상") steps.push([`${fp.service} 심화 열거`, "식별된 스택/버전 기준으로 알려진 이슈를 좁혀 exploit 단계 전 근거를 확보하세요."]);
  if (!steps.length) {
    const ran = eventsOf(s).some((e) => e.type === "tool_result");
    if (ran) steps.push(["정찰 확대", "유의미한 발견이 없었습니다. 목표/포트를 바꾸거나 다른 provider(모델)로 계획을 다양화해 재실행하세요."]);
    else steps.push(["세션 실행", "오른쪽 에이전트에 목표를 지시해 첫 engagement 를 실행하세요. 대상은 인가 목록(scope) 안이어야 합니다."]);
  }
  const blocked = eventsOf(s).filter((e) => e.type === "blocked");
  if (blocked.length) steps.push(["차단된 액션 확인", `ScopeGuard 가 ${blocked.length}건을 차단했습니다. 인가 범위/기간/포트 설정을 검토하세요.`]);
  return steps;
}
function renderNext(s) {
  $("view-next").innerHTML = nextSteps(s).map(([t, d], i) =>
    `<div class="next-item"><div class="num">${i + 1}</div><div class="body"><b>${esc(t)}</b><br/><span>${esc(d)}</span></div></div>`).join("");
}

// ── 대화 ─────────────────────────────────────────────────────────────────────
function renderChat() {
  const s = cur();
  const el = $("chatMessages");
  const chat = (s && s.chat) || [];
  if (!chat.length) { el.innerHTML = `<div class="placeholder">목표를 지시해 오퍼레이션을 시작하세요.<br/>에이전트가 방법을 찾아 왼쪽에 진행 상황을 보여줍니다.</div>`; return; }
  el.innerHTML = chat.map((m) => `<div class="msg ${m.role}">${esc(m.content)}<span class="ts">${hhmm(m.ts)}</span></div>`).join("");
  el.scrollTop = el.scrollHeight;
}

// ── 현재 활동(메인 패널 헤드라인): 지금 하는 일을 사람 말로 ──────────────────
// 툴 이름을 사람이 읽는 짧은 동작으로.
const TOOL_LABEL = {
  http_probe: "웹 응답 파악",
  header_audit: "보안 헤더 점검",
  waf_detect: "WAF/방화벽 식별",
  crawl: "링크·폼 크롤(공격 표면 수집)",
  jwt_audit: "JWT 토큰 정적 분석",
  port_scan: "포트 스캔",
  dir_enum: "경로 열거",
  api_discover: "backend API 발견",
  api_probe: "API 노출 정보 확인",
  cookie_audit: "세션 쿠키 플래그 점검",
  cors_audit: "CORS 신뢰정책 점검",
  secret_scan: "노출 비밀·백업 파일 스캔",
  graphql_probe: "GraphQL 스키마 노출 확인",
  csrf_audit: "CSRF 방어(토큰) 점검",
  upload_probe: "파일 업로드 제한 점검",
  sqli_probe: "SQLi 신호 탐지(오류·블라인드)",
  xss_probe: "반사형 XSS 탐지",
  path_traversal: "경로 조작·LFI 시도",
  open_redirect: "오픈 리다이렉트 확인",
  ssrf_probe: "SSRF 신호 관찰",
  idor_probe: "IDOR·접근통제 점검",
  ssti_probe: "서버측 템플릿 인젝션 탐지",
  cmdi_probe: "OS 커맨드 인젝션 탐지",
  xxe_probe: "XXE(내부 엔티티) 탐지",
};
function toolLabel(name) { return TOOL_LABEL[name] || name; }

function activityLine(e) {
  switch (e.type) {
    case "authorized": return "대상 인가 확인 — 정찰을 준비합니다";
    case "phase": return ({
      recon: "정찰(recon) — 대상 표면을 파악합니다",
      enumerate: "열거(enumerate) — 경로·서비스를 나열합니다",
      exploit: "공략(exploit) — 취약점 신호를 검증합니다",
      post: "정리(post) — 결과를 종합합니다",
    })[e.phase] || `${e.phase} 단계`;
    case "action": return `${e.phase} · ${toolLabel(e.tool)} 실행 중` + (e.rationale ? ` — ${e.rationale}` : "");
    case "tool_result": return `${toolLabel(e.tool)} 결과 — ${e.summary || (e.ok ? "완료" : "실패")}`;
    case "finding": return e.finding ? `발견: ${e.finding.title}` : "발견";
    case "distilled": return `학습 저장 — ${e.title || ""}`;
    case "blocked": return `차단됨 — ${e.tool || "액션"} (인가 범위 밖)`;
    case "done": return "완료 — 결과를 정리했습니다";
    default: return null;
  }
}
function setActivity(text) {
  const bar = $("activityBar"); if (!bar || !text) return;
  $("activityText").textContent = text;
  bar.classList.remove("hidden");
}
function hideActivity() { const b = $("activityBar"); if (b) b.classList.add("hidden"); }

// ── 대화창 마일스톤: 결과·추가요청만 assistant 메시지로 ──────────────────────
function milestoneChat(e) {
  if (e.type === "finding" && e.finding) {
    const f = e.finding;
    return `발견 · [${(f.severity || "info").toUpperCase()}] ${f.title}` + (f.detail ? `\n${f.detail}` : "");
  }
  if (e.type === "blocked") {
    return `권한 밖 액션이 차단되었습니다: ${e.tool || "액션"}.\n계속하려면 설정(⚙)에서 authorization scope를 확장한 뒤 다시 실행하세요.`;
  }
  if (e.type === "error") return `실행 중 오류가 발생했습니다: ${e.text || ""}`.trim();
  return null;
}
async function pushAssistant(id, content) {
  await invoke("append_chat", { id, role: "assistant", content });
  const fresh = await invoke("get_session", { id });
  if (fresh) { const i = sessions.findIndex((x) => x.id === id); if (i >= 0) sessions[i] = fresh; }
  if (id === activeId) renderChat();
}

// ── 라이브 이벤트 반영 ───────────────────────────────────────────────────────
function onLiveEvent(event) {
  const s = cur(); if (!s) return;
  const body = $("capBody");
  $("capEmpty").style.display = "none";
  const seq = event._seq != null ? event._seq : eventsOf(s).length - 1;
  body.insertAdjacentHTML("beforeend", rowHtml(event, seq));
  const lastTr = body.lastElementChild;
  if (lastTr) lastTr.onclick = () => {
    selectedSeq = parseInt(lastTr.dataset.seq, 10);
    document.querySelectorAll("#capBody tr").forEach((x) => x.classList.remove("sel"));
    lastTr.classList.add("sel");
    renderDetail(event);
  };
  const cap = document.querySelector(".capture");
  if (cap) cap.scrollTop = cap.scrollHeight;

  renderStepper(s);
  renderMetrics(s);
  if (event.type === "finding") renderFindings(s);
  if (event.type === "done") { renderFindings(s); renderIntel(s); renderNext(s); }

  // 메인 패널 헤드라인 갱신 + 결과/요청은 대화창으로
  const line = activityLine(event);
  if (line) setActivity(line);
  const ms = milestoneChat(event);
  if (ms) pushAssistant(s.id, ms);
  if (event.type === "done") hideActivity();
}

async function onFinished(id, status) {
  const fresh = await invoke("get_session", { id });
  if (fresh) { const i = sessions.findIndex((x) => x.id === id); if (i >= 0) sessions[i] = fresh; }
  const s = sessions.find((x) => x.id === id);
  const fs = findingsOf(s);
  const sev = {}; fs.forEach((f) => { sev[f.severity] = (sev[f.severity] || 0) + 1; });
  const summary = status === "error"
    ? "실행이 오류로 종료되었습니다. ‘라이브 캡처’에서 원인을 확인하세요."
    : `완료 — 발견 ${fs.length}건` + (fs.length ? ` (${Object.entries(sev).map(([k, v]) => `${k}:${v}`).join(", ")})` : "") + `. ‘다음 단계’ 탭에 권고를 정리했습니다.`;
  await invoke("append_chat", { id, role: "assistant", content: summary });
  const upd = await invoke("get_session", { id });
  if (upd) { const i = sessions.findIndex((x) => x.id === id); sessions[i] = upd; }
  if (id === activeId) { renderChat(); renderNext(cur()); renderStepper(cur()); }
}

// ── 액션 ─────────────────────────────────────────────────────────────────────
async function selectSession(id) {
  activeId = id;
  const fresh = await invoke("get_session", { id });
  if (fresh) { const i = sessions.findIndex((x) => x.id === id); if (i >= 0) sessions[i] = fresh; }
  renderTabs();
  renderActive();
  switchView("live");
}

async function newSession() {
  const s = await invoke("create_session", { name: "", host: "127.0.0.1", port: null, goal: "", provider: settings.default_provider || "", mode: "tools" });
  sessions.unshift(s);
  activeId = s.id;
  renderTabs();
  renderActive();
  $("shHost").focus();
}

async function removeSession(id) {
  if (!confirm("이 세션을 삭제할까요? 저장된 로그도 함께 삭제됩니다.")) return;
  await invoke("delete_session", { id });
  sessions = sessions.filter((x) => x.id !== id);
  if (activeId === id) activeId = sessions[0] ? sessions[0].id : null;
  renderTabs();
  renderActive();
}

async function persistHeader(overrides = {}) {
  const s = cur(); if (!s) return;
  // host 란에 URL(http://…) 또는 host:port 를 넣으면 분해해 각 입력란에 반영한다.
  const norm = normalizeTargetInput($("shHost").value);
  const hostRaw = $("shHost").value.trim();
  if (norm.host !== hostRaw) $("shHost").value = norm.host;
  const portField = $("shPort").value.trim();
  if (norm.port && !portField) $("shPort").value = norm.port;
  const portRaw = $("shPort").value.trim();
  const port = portRaw ? parseInt(portRaw, 10) : null;
  const payload = {
    id: s.id,
    name: $("shName").value.trim() || s.name,
    host: norm.host || hostRaw,
    port: Number.isInteger(port) && port > 0 && port <= 65535 ? port : null,
    goal: overrides.goal !== undefined ? overrides.goal : s.goal,
    provider: $("shProvider").value,
    mode: $("shMode") ? $("shMode").value : "tools",
  };
  const updated = await invoke("update_session", payload);
  if (updated) { const i = sessions.findIndex((x) => x.id === s.id); sessions[i] = updated; }
  renderTabs();
}

// ── 대상 자동 인가: 입력한 host/URL 을 실행 시 인가 목록에 자동 추가 ────────────
function normalizeTargetInput(raw) {
  const v = (raw || "").trim();
  let host = v;
  let port = null;
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(v)) {
    try {
      const u = new URL(v);
      host = (u.hostname || "").replace(/^\[|\]$/g, ""); // IPv6 [::1] → ::1
      port = u.port || null;
    } catch { /* URL 아님 — 그대로 */ }
  } else {
    const m = /^(.+):(\d{1,5})$/.exec(v); // host:port (스킴 없이)
    if (m) { host = m[1]; port = m[2]; }
  }
  return { host, port };
}

async function ensureTargetAuthorized() {
  const s = cur(); if (!s) return;
  const host = (s.host || "").trim();
  if (!host) return;
  try {
    const r = await invoke("auth_ensure", { host });
    if (r.yaml) {
      await pushAssistant(s.id, `인가 파일이 정식 YAML 입니다 — 대상 ${r.host} 을(를) 자동 추가하지 않았습니다. 인가 범위는 엔진(ScopeGuard)이 그대로 강제합니다.`);
    } else if (r.added) {
      await pushAssistant(s.id, `대상 ${r.host} 을(를) 인가 목록에 자동 추가했습니다. 빼려면 🛡 인가 대상 관리에서 제거하세요.`);
    } else if (r.existed) {
      await pushAssistant(s.id, `대상 ${r.host} 은(는) 이미 인가된 대상입니다.`);
    }
  } catch (e) {
    await pushAssistant(s.id, `대상 자동 인가 실패: ${e} — 인가 범위는 엔진이 계속 강제합니다.`);
  }
}

async function runEngagement() {
  const s = cur(); if (!s) return;
  if (!s.host && !$("shHost").value.trim()) { alert("host 를 먼저 입력하세요."); return; }
  await persistHeader();
  if (!activeProvider()) { showProviderModal(); return; } // 미설정 → 모달로 설정 유도
  await ensureTargetAuthorized();
  try {
    setBadge("running");
    await invoke("start_engagement", { id: s.id });
  } catch (e) {
    setBadge("error");
    const msg = "실행 실패: " + e;
    await invoke("append_chat", { id: s.id, role: "system", content: msg });
    const fresh = await invoke("get_session", { id: s.id });
    if (fresh) { const i = sessions.findIndex((x) => x.id === s.id); sessions[i] = fresh; }
    renderChat();
    alert(msg); // 스폰 실패(전형적: Windows npx 문제, redcell 경로/의존성)를 즉시 알린다
  }
}

async function stopEngagement() {
  const s = cur(); if (!s) return;
  try {
    await invoke("stop_engagement", { id: s.id });
  } catch (e) {
    // 이미 종료됐거나 지원되지 않으면 무시
  }
}

// 실행 버튼: 실행 중이면 중지, 아니면 실행(재실행)
function onRunButton() {
  const btn = $("runBtn");
  if (btn.dataset.mode === "stop") return stopEngagement();
  return runEngagement();
}

async function sendChat() {
  const s = cur(); if (!s) return;
  const input = $("chatInput");
  const text = input.value.trim();
  if (!text) return;
  if (!activeProvider()) { showProviderModal(); return; } // 입력 보존 + 설정 유도
  input.value = "";
  await persistHeader({ goal: text });
  await invoke("append_chat", { id: s.id, role: "user", content: text });
  const host = $("shHost").value.trim();
  const port = $("shPort").value.trim();
  const provider = activeProvider();
  const target = host ? `${host}${port ? ":" + port : ""}` : "(대상 미지정 — host 를 입력하세요)";
  let ack;
  if (s.status === "running") {
    ack = `목표 "${text}" 을(를) 저장했습니다. 현재 실행이 진행 중입니다 — 완료 후 이 목표로 다시 실행됩니다.`;
  } else {
    ack = `목표 반영: "${text}"\n대상 ${target} · 프로바이더 ${provider} 로 실행합니다 — 왼쪽 라이브 캡처에서 진행을 확인하세요.`;
  }
  await invoke("append_chat", { id: s.id, role: "assistant", content: ack });
  const fresh = await invoke("get_session", { id: s.id });
  if (fresh) { const i = sessions.findIndex((x) => x.id === s.id); sessions[i] = fresh; }
  renderChat();
  switchView("live");
  if (s.status !== "running") await runEngagement();
}

// ── 프로바이더: 연결된 것만 리스트에 노출, 미설정 시 모달 유도 ────────────────
// 엔진 레지스트리(redcell/src/providers/registry.ts)와 동일하게 유지한다.
const PROVIDER_CATALOG = [
  { name: "anthropic", kind: "anthropic", note: "Claude 공식 API", default_model: "claude-opus-5", envKeys: ["ANTHROPIC_OAUTH_TOKEN", "ANTHROPIC_API_KEY"], baseUrl: "https://api.anthropic.com/v1", needsBase: false },
  { name: "openai", kind: "openai-compat", note: "GPT 공식 API", default_model: "gpt-5.4", envKeys: ["OPENAI_API_KEY"], baseUrl: "https://api.openai.com/v1", needsBase: false },
  { name: "openrouter", kind: "openai-compat", note: "다수 모델 게이트웨이", default_model: "moonshotai/kimi-k2.6", envKeys: ["OPENROUTER_API_KEY"], baseUrl: "https://openrouter.ai/api/v1", needsBase: false },
  { name: "prime-inference", kind: "openai-compat", note: "Prime Intellect inference", default_model: "z-ai/glm-5.2", envKeys: ["PRIME_API_KEY"], baseUrl: "https://api.pinference.ai/api/v1", needsBase: false },
  { name: "groq", kind: "openai-compat", note: "고속 추론", default_model: "openai/gpt-oss-120b", envKeys: ["GROQ_API_KEY"], baseUrl: "https://api.groq.com/openai/v1", needsBase: false },
  { name: "cerebras", kind: "openai-compat", note: "Cerebras 초고속 추론", default_model: "gpt-oss-120b", envKeys: ["CEREBRAS_API_KEY"], baseUrl: "https://api.cerebras.ai/v1", needsBase: false },
  { name: "xai", kind: "openai-compat", note: "xAI Grok", default_model: "grok-4.20-0309-reasoning", envKeys: ["XAI_API_KEY"], baseUrl: "https://api.x.ai/v1", needsBase: false },
  { name: "deepseek", kind: "openai-compat", note: "DeepSeek", default_model: "deepseek-v4-pro", envKeys: ["DEEPSEEK_API_KEY"], baseUrl: "https://api.deepseek.com", needsBase: false },
  { name: "mistral", kind: "openai-compat", note: "Mistral AI", default_model: "devstral-medium-latest", envKeys: ["MISTRAL_API_KEY"], baseUrl: "https://api.mistral.ai/v1", needsBase: false },
  { name: "moonshotai", kind: "openai-compat", note: "Moonshot Kimi", default_model: "kimi-k2.6", envKeys: ["MOONSHOT_API_KEY"], baseUrl: "https://api.moonshot.ai/v1", needsBase: false },
  { name: "zai", kind: "openai-compat", note: "Z.ai GLM", default_model: "glm-5.1", envKeys: ["ZAI_API_KEY"], baseUrl: "https://api.z.ai/api/coding/paas/v4", needsBase: false },
  { name: "ollama", kind: "openai-compat", note: "로컬/원격 ollama 서버 (키 불필요)", default_model: "llama3.1", envKeys: [], baseUrl: "http://localhost:11434/v1", needsBase: true },
  { name: "custom", kind: "openai-compat", note: "임의 OpenAI 호환 엔드포인트 — vLLM·LM Studio·원격 ollama 등", default_model: "", envKeys: ["REDCELL_OPENAI_API_KEY"], baseUrl: "", needsBase: true },
];
let envReadyMap = {}; // get_providers 의 ready_env (시스템 환경변수 감지)
let expandedProvider = null;

function activeProvider() {
  const sel = $("shProvider");
  const v = sel && sel.value ? sel.value.trim() : "";
  return v && v !== "mock" ? v : "";
}
function showProviderModal() {
  $("providerModal").classList.remove("hidden");
}

// 연결됨 판정: 설정에 저장된 키/base URL 또는 시스템 환경변수 중 하나.
function providerConnected(p) {
  const c = (settings.providers || {})[p.name];
  if (envReadyMap[p.name]) return true; // 시스템 환경변수로 연결
  if (!c) return false;
  if (p.name === "custom") return !!(c.base_url); // base URL 필수
  if (p.needsBase) return true; // ollama: 저장만 하면 기본 localhost base URL 사용
  return !!(c.api_key); // API 키 저장 여부
}
function providerConnState(p) {
  const c = (settings.providers || {})[p.name] || {};
  return {
    api_key: c.api_key || "",
    base_url: c.base_url || "",
    model: c.model || "",
    connected: providerConnected(p),
    viaEnv: !!envReadyMap[p.name],
  };
}

function renderProviderCards() {
  const el = $("providerCards");
  if (!el) return;
  el.innerHTML = PROVIDER_CATALOG.map((p) => {
    const st = providerConnState(p);
    const keyLabel = p.envKeys.length ? p.envKeys[p.envKeys.length - 1] : "";
    const basePlaceholder = p.name === "ollama" ? "http://localhost:11434/v1" : "https://your-endpoint/v1";
    const modelPh = p.default_model || "예: gpt-4o";
    const open = expandedProvider === p.name;
    return `<div class="pcard${st.connected ? " connected" : ""}${open ? " open" : ""}" data-provider="${p.name}">
      <div class="pcard-head" data-act="toggle" role="button" tabindex="0" aria-expanded="${open}">
        <span class="led ${st.connected ? "on" : ""}"></span>
        <span class="pcard-name">${p.name}</span>
        <span class="pcard-kind">${p.kind}</span>
        <span class="pcard-note">${esc(p.note)}</span>
        <span class="pcard-state ${st.connected ? "ok" : ""}">${st.connected ? (st.viaEnv ? "환경변수" : "연결됨") : "미연결"}</span>
        <svg class="ic pcard-chev"><use href="#i-chev"/></svg>
      </div>
      <div class="pcard-body">
        ${p.needsBase ? `<label class="fld"><span>Base URL</span><input class="sh-input mono" data-f="base" value="${esc(st.base_url || p.baseUrl)}" placeholder="${basePlaceholder}" spellcheck="false" /></label>` : ""}
        ${p.envKeys.length ? `<label class="fld"><span>API 키 <span class="lbl-dim">(${keyLabel})</span></span>
          <span class="pcard-keyrow">
            <input class="sh-input mono" data-f="key" type="password" value="${esc(st.api_key)}" placeholder="sk-…" spellcheck="false" autocomplete="off" />
            <button class="btn btn-icon" data-act="eye" title="표시/숨김" aria-label="키 표시/숨김"><svg class="ic"><use href="#i-eye"/></svg></button>
          </span>
        </label>` : ""}
        <label class="fld"><span>모델 <span class="lbl-dim">(선택 — 비우면 기본 ${p.default_model || "엔드포인트 기본"})</span></span><input class="sh-input mono" data-f="model" value="${esc(st.model)}" placeholder="${modelPh}" spellcheck="false" /></label>
        <div class="pcard-actions">
          <span class="pcard-test" data-r></span>
          <button class="btn btn-ghost" data-act="test">연결 테스트</button>
          <button class="btn btn-primary" data-act="save">연결 저장</button>
        </div>
      </div>
    </div>`;
  }).join("");
}

function cardValues(card) {
  const q = (sel) => { const i = card.querySelector(sel); return i ? i.value.trim() : ""; };
  return { api_key: q('[data-f="key"]'), base_url: q('[data-f="base"]'), model: q('[data-f="model"]') };
}

function collectSettings(providers) {
  return {
    redcell_dir: $("setRedcellDir").value.trim(),
    auth_path: $("setAuthPath").value.trim(),
    default_provider: $("setProviderDefault") ? $("setProviderDefault").value : settings.default_provider,
    providers,
  };
}

async function saveSettingsNow(providers) {
  settings = await invoke("save_settings", { settings: collectSettings(providers) });
  await refreshProviders();
  renderProviderDefaultSelect();
  renderProviderCards();
  updateConnSummary();
}

function renderProviderDefaultSelect() {
  const sel = $("setProviderDefault");
  if (!sel) return;
  const connected = PROVIDER_CATALOG.filter(providerConnected);
  sel.innerHTML = `<option value="">(선택 안 함)</option>`
    + connected.map((p) => `<option value="${p.name}">${p.name} ✅</option>`).join("");
  sel.value = settings.default_provider || "";
}

async function testProviderConn(card, p) {
  const out = card.querySelector("[data-r]");
  if (!out) return;
  const v = cardValues(card);
  out.textContent = "확인 중…";
  out.className = "pcard-test";
  try {
    const res = await invoke("test_provider", { provider: p.name, apiKey: v.api_key, baseUrl: v.base_url || p.baseUrl });
    out.textContent = "✅ " + res;
    out.className = "pcard-test ok";
  } catch (e) {
    out.textContent = "❌ " + e;
    out.className = "pcard-test err";
  }
}

function wireProviderCards() {
  const el = $("providerCards");
  if (!el) return;
  el.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    const head = e.target.closest(".pcard-head");
    if (!head) return;
    e.preventDefault();
    head.click();
  });
  el.addEventListener("click", async (e) => {
    const card = e.target.closest(".pcard");
    const actEl = e.target.closest("[data-act]");
    if (!card || !actEl) return;
    const name = card.dataset.provider;
    const p = PROVIDER_CATALOG.find((x) => x.name === name);
    if (!p) return;
    const act = actEl.dataset.act;
    if (act === "toggle") {
      expandedProvider = expandedProvider === name ? null : name;
      renderProviderCards();
    } else if (act === "eye") {
      const k = card.querySelector('[data-f="key"]');
      if (k) k.type = k.type === "password" ? "text" : "password";
    } else if (act === "test") {
      await testProviderConn(card, p);
    } else if (act === "save") {
      const providers = Object.assign({}, settings.providers || {});
      const v = cardValues(card);
      if (v.api_key || v.base_url || v.model) providers[name] = v;
      else delete providers[name];
      await saveSettingsNow(providers);
      const out2 = card.querySelector("[data-r]");
      if (out2) { out2.textContent = "💾 저장됨 — 상단 드롭다운에 반영됩니다"; out2.className = "pcard-test ok"; }
    }
  });
}

async function refreshProviders() {
  let list;
  try { list = await invoke("get_providers"); } catch { return; } // preview/mock 환경
  if (!Array.isArray(list)) return;
  envReadyMap = {};
  list.forEach((p) => { envReadyMap[p.name] = !!p.ready_env; });
  const connected = PROVIDER_CATALOG.filter(providerConnected);
  const sel = $("shProvider");
  if (sel) {
    const prev = sel.value;
    sel.innerHTML = `<option value="">— provider 선택 —</option>`
      + connected.map((p) => `<option value="${esc(p.name)}">${esc(p.name)} ✅</option>`).join("");
    const want = (cur() && cur().provider) || settings.default_provider || "";
    sel.value = connected.some((p) => p.name === want) ? want
      : (prev && connected.some((p) => p.name === prev) ? prev : "");
  }
  const hint = $("providerHint");
  if (hint) {
    const names = connected.map((p) => p.name);
    hint.textContent = names.length
      ? `연결됨: ${names.join(", ")} — 상단 드롭다운에서 선택하세요. 지시가 실제 LLM 추론에 반영됩니다.`
      : "연결된 프로바이더가 없습니다 — 설정(⚙) > 모델 연결 에서 API 키를 입력하고 [연결 저장] 하세요. 키는 이 PC에만 저장되고 실행 시 자동 주입됩니다.";
  }
}

// ── 뷰 전환 ──────────────────────────────────────────────────────────────────
function switchView(name) {
  document.querySelectorAll(".subtab").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  const isLive = name === "live";
  $("view-live").classList.toggle("active", isLive);
  document.querySelector(".view-scroll-wrap").style.display = isLive ? "none" : "flex";
  ["findings", "intel", "next"].forEach((v) => $("view-" + v).classList.toggle("active", v === name));
}

// ── 설정 ─────────────────────────────────────────────────────────────────────
function updateConnSummary() {
  const el = $("connSummary");
  if (!el) return;
  const connected = PROVIDER_CATALOG.filter(providerConnected);
  const n = connected.length;
  const names = connected.map((p) => p.name).join(", ");
  el.innerHTML = `<span class="s-dot ${n ? "on" : ""}"></span>`
    + (n
      ? `연결됨 ${n}/${PROVIDER_CATALOG.length} — ${esc(names)}`
      : `연결된 프로바이더 없음 (${PROVIDER_CATALOG.length}종 지원) — 아래에서 연결하세요`);
}

function openSettings() {
  $("setRedcellDir").value = settings.redcell_dir || "";
  $("setAuthPath").value = settings.auth_path || "";
  renderProviderCards();
  renderProviderDefaultSelect();
  updateConnSummary();
  $("settingsModal").classList.remove("hidden");
}
async function saveSettings() {
  // 카드에 입력된 값까지 수집해 한 번에 저장 (카드별 [연결 저장] 없이도 동작)
  const providers = {};
  document.querySelectorAll("#providerCards .pcard").forEach((card) => {
    const v = cardValues(card);
    if (v.api_key || v.base_url || v.model) providers[card.dataset.provider] = v;
  });
  await saveSettingsNow(providers);
  $("settingsModal").classList.add("hidden");
}

// ── 인가 대상 관리 (ip-list) — UI 에서 IP 추가/제거 ─────────────────────────
let authState = null;
let authDenyMode = false; // 추가 방식: false=허용, true=제외

function showAuthError(msg) {
  const el = $("authError");
  el.textContent = msg || "";
  el.classList.toggle("hidden", !msg);
}

function setAuthPill(kind, text) {
  const p = $("authPill");
  p.className = "auth-pill" + (kind ? " " + kind : "");
  p.textContent = text;
}

function setSeg(deny) {
  authDenyMode = deny;
  $("segAllow").classList.toggle("active", !deny);
  $("segDeny").classList.toggle("active", deny);
  $("segAllow").setAttribute("aria-pressed", String(!deny));
  $("segDeny").setAttribute("aria-pressed", String(deny));
}

// 대상 문자열 → 유형 태그 (IP / CIDR / IPv6 / 도메인 / 호스트)
function kindOf(t) {
  if (t.includes("/")) return "CIDR";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) return "IP";
  if (t.includes(":")) return "IPv6";
  if (t.startsWith("*.")) return "도메인";
  return "호스트";
}

async function loadAuth() {
  showAuthError(null);
  try {
    authState = await invoke("list_auth");
    renderAuth();
    $("authTarget").focus();
  } catch (e) {
    setAuthPill("err", "읽기 오류");
    showAuthError(String(e));
  }
}

function renderAuth() {
  const a = authState || {};
  $("authPathInfo").textContent = a.path || "(미지정)";

  // 상태 필(pill)
  const allowList = a.allows || [];
  if (a.yaml) setAuthPill("warn", "YAML 인가 파일");
  else if (a.error) setAuthPill("err", "읽기 오류");
  else if (a.empty) setAuthPill("warn", "목록 비어 있음");
  else if (a.warn) setAuthPill("warn", "허용 0건");
  else setAuthPill("ok", `허용 ${allowList.length}개`);

  // YAML/경고 안내
  const yamlWarn = $("authYamlWarn");
  if (a.yaml) {
    yamlWarn.classList.remove("hidden");
    yamlWarn.innerHTML = `<svg class="ic ic-sm"><use href="#i-shield"/></svg><div><b>정식 YAML 인가 파일입니다.</b> IP 추가/제거는 이 파일을 편집하지 않습니다.<br/>⚙ 설정에서 auth 경로를 비우면 기본 IP 목록(<code>${esc(a.default_path || "~/.redcell/authorization.list")}</code>)을 관리합니다.</div>`;
  } else if (a.warn) {
    yamlWarn.classList.remove("hidden");
    yamlWarn.innerHTML = `<svg class="ic ic-sm"><use href="#i-shield"/></svg><div><b>허용 대상이 없습니다.</b> 아래에서 IP를 추가하세요 — 추가하는 순간 인가된 대상이 됩니다.</div>`;
  } else {
    yamlWarn.classList.add("hidden");
  }

  // 목록
  $("authAllowList").innerHTML = allowList.map(authItemHtml).join("");
  $("authDenyList").innerHTML = (a.denies || []).map(authItemHtml).join("");
  $("authAllowCnt").textContent = allowList.length;
  $("authDenyCnt").textContent = (a.denies || []).length;
  $("authAllowEmpty").classList.toggle("hidden", allowList.length > 0);
  $("authDenyEmpty").classList.toggle("hidden", (a.denies || []).length > 0);

  // 메타 칩
  $("authMeta").innerHTML = [
    `<span class="auth-chip">유효기간 <b>${esc(a.until || "기본 +365일")}</b></span>`,
    `<span class="auth-chip">허용 포트 <b>${a.ports && a.ports.length ? esc(a.ports.join(", ")) : "전체"}</b></span>`,
    `<span class="auth-chip">RPS <b>10/s</b></span>`,
  ].join("");

  if (a.empty) showAuthError("인가 목록이 비어 있습니다 — 아래에서 IP를 추가하세요. 목록에 들어간 대상만 인가됩니다.");
  else if (a.error) showAuthError(a.error);
}

function authItemHtml(target) {
  const tag = kindOf(target);
  return `<li class="auth-item" data-target="${esc(target)}">
    <span class="auth-kind">${tag}</span>
    <span class="auth-target">${esc(target)}</span>
    <button class="btn btn-icon auth-rm" title="제거" aria-label="${esc(target)} 제거"><svg class="ic ic-sm"><use href="#i-x"/></svg></button>
  </li>`;
}

function findAuthItem(target) {
  return [...document.querySelectorAll("#authAllowList .auth-item, #authDenyList .auth-item")]
    .find((li) => li.dataset.target === target) || null;
}

async function addAuth() {
  const input = $("authTarget");
  const target = input.value.trim();
  if (!target) return;
  try {
    authState = await invoke("add_auth", { target, deny: authDenyMode });
    input.value = "";
    renderAuth();
    // 방금 추가된 항목에 짧은 플래시(성공 피드백)
    const li = findAuthItem(target);
    if (li) {
      li.classList.add("flash");
      setTimeout(() => li.classList.remove("flash"), 950);
    }
    input.focus();
  } catch (e) {
    showAuthError(String(e));
  }
}

async function removeAuth(target) {
  if (!confirm(`"${target}" 을(를) 인가 목록에서 제거할까요?`)) return;
  const li = findAuthItem(target);
  if (li) {
    li.classList.add("removing"); // 페이드아웃 후 반영
    await new Promise((r) => setTimeout(r, 190));
  }
  try {
    authState = await invoke("remove_auth", { target });
    renderAuth();
  } catch (e) {
    showAuthError(String(e));
    if (li) li.classList.remove("removing");
  }
}

function openAuth() {
  setSeg(false);
  $("authModal").classList.remove("hidden");
  loadAuth();
}

// ── 배선 ─────────────────────────────────────────────────────────────────────
function wire() {
  $("newSessionBtn").onclick = newSession;
  $("emptyNewBtn").onclick = newSession;
  $("settingsBtn").onclick = openSettings;
  $("settingsCancel").onclick = () => $("settingsModal").classList.add("hidden");
  $("settingsClose").onclick = () => $("settingsModal").classList.add("hidden");
  $("settingsSave").onclick = saveSettings;
  $("providerGoto").onclick = () => { $("providerModal").classList.add("hidden"); openSettings(); };
  $("providerClose").onclick = () => $("providerModal").classList.add("hidden");
  wireProviderCards();
  // 모달 공통: 바깥 클릭 / Esc 로 닫기
  ["settingsModal", "authModal", "providerModal"].forEach((id) => {
    const m = $(id);
    if (!m) return;
    m.addEventListener("pointerdown", (e) => { if (e.target === m) m.classList.add("hidden"); });
  });
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    ["settingsModal", "authModal", "providerModal"].forEach((id) => { const m = $(id); if (m && !m.classList.contains("hidden")) m.classList.add("hidden"); });
  });
  $("runBtn").onclick = onRunButton;
  $("chatSend").onclick = sendChat;
  $("chatInput").addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendChat(); } });
  $("scopeBtn").onclick = openAuth;
  $("authClose").onclick = () => $("authModal").classList.add("hidden");
  $("authRefresh").onclick = loadAuth;
  $("authAdd").onclick = addAuth;
  $("segAllow").onclick = () => setSeg(false);
  $("segDeny").onclick = () => setSeg(true);
  $("authTarget").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); addAuth(); } });
  ["authAllowList", "authDenyList"].forEach((id) => {
    $(id).addEventListener("click", (e) => {
      const b = e.target.closest(".auth-rm");
      if (b) removeAuth(b.dataset.target);
    });
  });
  const qg = $("quickGoals");
  if (qg) qg.addEventListener("click", (e) => {
    const b = e.target.closest(".chip");
    if (!b) return;
    $("chatInput").value = b.dataset.goal || b.textContent.trim();
    sendChat();
  });
  ["shName", "shHost", "shPort", "shProvider", "shMode"].forEach((id) => $(id) && $(id).addEventListener("change", () => persistHeader()));
  document.querySelectorAll(".subtab").forEach((btn) => { btn.onclick = () => switchView(btn.dataset.view); });
}

async function listenEngagement() {
  await listen("engagement-event", (evt) => {
    const { sessionId, event } = evt.payload;
    const s = sessions.find((x) => x.id === sessionId);
    if (s) { s.events = s.events || []; s.events.push(event); }
    if (sessionId === activeId) onLiveEvent(event);
  });
  await listen("engagement-status", (evt) => {
    const { sessionId, status } = evt.payload;
    const s = sessions.find((x) => x.id === sessionId);
    if (s) s.status = status;
    renderTabs();
    if (sessionId === activeId) setBadge(status);
    if (status === "done" || status === "error") onFinished(sessionId, status);
    if (status === "stopped") pushAssistant(sessionId, "실행을 중지했습니다. '재실행'을 누르면 현재 목표로 다시 시작합니다.");
  });
}

async function boot() {
  if (!TAURI) {
    document.body.innerHTML = '<div class="placeholder" style="margin-top:80px">이 페이지는 Tauri 앱 안에서 실행해야 합니다.<br/>터미널에서 <code>cargo tauri dev</code> 로 띄우세요.</div>';
    return;
  }
  wire();
  switchView("live");
  settings = await invoke("get_settings");
  sessions = await invoke("list_sessions");
  activeId = sessions.length ? sessions[0].id : null;
  renderTabs();
  renderActive();
  await listenEngagement();
  await refreshProviders();
}

window.addEventListener("DOMContentLoaded", boot);
