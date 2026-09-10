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
let diagFilter = null; // 진단 결과 루트 필터: null=전체, Set(치명|높음|중간|낮음)

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
  const psel = $("shProvider");
  if (psel) {
    const want = s.provider || settings.default_provider || "";
    const clean = want === "mock" ? "" : want; // 레거시 mock 값은 선택지로 삼지 않음
    if (clean && ![...psel.options].some((o) => o.value === clean)) {
      psel.insertAdjacentHTML("beforeend", `<option value="${esc(clean)}">${esc(clean)} (저장됨)</option>`);
    }
    psel.value = clean;
  }
  const chatInput = $("chatInput");
  if (chatInput) {
    chatInput.placeholder = (s && s.diag)
      ? "서비스 설명을 넣으면 더 정밀하게 — 없어도 URL 만으로 실측 정찰 후 진단합니다"
      : "대상이 있으면 위에 host/URL 을 입력하세요 · 지시 예: \"하반기 합격자 목록을 파일로 뽑아줘\"";
  }
  const dc = $("diagChk");
  if (dc) dc.checked = !!(s && s.diag);
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
  btn.title = running ? "실행 중지" : "prime-agent 실행 — URL 을 위에, 지시는 오른쪽 패널에서";
  $("runIcon").innerHTML = '<use href="#' + (running ? "i-stop" : "i-play") + '"/>';
  $("runLabel").textContent = running ? "중지" : status === "idle" ? "실행" : "재실행";
  const state = $("agentState");
  state.textContent = running ? "작동 중" : (status === "done" ? "완료" : status === "error" ? "오류" : status === "stopped" ? "중지됨" : "대기");
  state.className = "agent-state" + (running ? " busy" : "");
  const actEl = $("activityText");
  if (running && actEl) setActivity(actEl.textContent || "prime-agent 가 작업 중…");
  else hideActivity();
}

// ── 캡처 테이블 ──────────────────────────────────────────────────────────────
function renderCapture(s) {
  if (resultsTabActive()) renderResults();
  const body = $("capBody");
  const evs = eventsOf(s);
  body.innerHTML = evs.map((e, i) => rowHtml(e, i)).join("");
  $("capEmpty").style.display = evs.length ? "none" : "block";
  wireRows();
  const cap = document.querySelector(".capture");
  if (cap) cap.scrollTop = cap.scrollHeight;
  renderPiConsole(s);
}

/** 좌측 패널을 pi CLI 화면(터미널)으로 렌더링한다 — 이 앱은 prime-agent(pi) 전용 셸이다. */
function renderPiConsole(s) {
  const live = $("view-live");
  const body = $("piConsoleBody");
  if (!live || !body) return;
  live.classList.add("pi-mode");
  const lines = [];
  let prevLine = null; // 연속 중복(이중 저장) 노트는 1개만
  for (const m of (s.chat || [])) {
    if (m.role === "user" && m.content.trim()) lines.push({ cls: "pi-user", text: m.content });
  }
  for (const e of eventsOf(s)) {
    const t = (e.text || e.reason || "").trim();
    if (!t) continue;
    if (t === prevLine) continue;
    prevLine = t;
    if (/^\[pi-툴\]/.test(t)) lines.push({ cls: "pi-tool", text: t });
    else if (/^\[sys\]/.test(t)) lines.push({ cls: "pi-sys", text: t });
    else if (e.type === "error" || /^\[오류\]/.test(t)) lines.push({ cls: "pi-error", text: t });
    else if (/^\[완료\]/.test(t) || e.type === "done" || t.startsWith("완료")) lines.push({ cls: "pi-done", text: t });
    else if (/발견|\[인텔\]/.test(t)) lines.push({ cls: "pi-find", text: t });
    else lines.push({ cls: "pi-text", text: t });
  }
  body.innerHTML = lines.length
    ? lines.map((l) => `<span class="${l.cls}">${esc(l.text)}</span>\n`).join("")
    : "prime-agent(pi) 대기 중 — 위에 대상 호스트/URL 을 넣고 지시를 보내면 CLI 처럼 여기에 스트리밍됩니다.";
  body.scrollTop = body.scrollHeight;
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
  if (!document.querySelector(".step")) return;
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
  if (!$("mEvents")) return;
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
  if (!el) return;
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
  if (!el) return;
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
  const el = $("view-next");
  if (!el) return;
  el.innerHTML = nextSteps(s).map(([t, d], i) =>
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
  web_fetch: "웹 페이지 조회(실측 확인)",
  recon_list: "경로 정찰(공격 표면 점검)",
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

  // pi CLI 화면(터미널)으로 동일 이벤트를 스트리밍.
  if (s) renderPiConsole(s);
  if (resultsTabActive()) renderResults();

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
  {
    const summary = status === "error"
      ? "prime-agent 가 오류로 종료되었습니다. 라이브 캡처의 [sys]/[오류] 노트를 확인하세요."
      : "완료 — 아래에서 이어서 지시할 수 있습니다(같은 대화로 이어집니다).";
    await invoke("append_chat", { id, role: "assistant", content: summary });
  }
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
  const s = await invoke("create_session", { name: "", host: "127.0.0.1", port: null, goal: "", provider: settings.default_provider || "", mode: "tools", max: false, diag: false });
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
    provider: ($("shProvider") && $("shProvider").value && $("shProvider").value !== "mock" ? $("shProvider").value : "") || (s.provider !== "mock" ? s.provider : "") || (settings.default_provider !== "mock" ? settings.default_provider : "") || "",
    diag: !!($("diagChk") && $("diagChk").checked) || !!s.diag,
    mode: "prime", // 이 앱은 prime-agent(pi) 전용 셸이다
    max: false,
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

// 인가 안내 메시지는 세션당 한 번만 띄운다(매 지시마다 auth_ensure 는 계속 호출되지만,
// "이미 인가된 대상입니다" 같은 반복 안내는 더 이상 알림으로 추가하지 않는다).
const authNotified = {};

async function ensureTargetAuthorized() {
  const s = cur(); if (!s) return;
  const host = (s.host || "").trim();
  if (!host) return;
  try {
    const r = await invoke("auth_ensure", { host });
    // 실제 인가 목록 반영(자동 추가)은 매번 수행 — 알림만 1회로 제한.
    const msg = r.yaml
      ? `인가 파일이 정식 YAML 입니다 — 대상 ${r.host} 을(를) 자동 추가하지 않았습니다. 인가 범위는 엔진(ScopeGuard)이 그대로 강제합니다.`
      : (() => {
          const ipNote = (r.ips_added && r.ips_added.length)
            ? ` 해석된 IP 도 함께 허용: ${r.ips_added.join(", ")}`
            : (r.ips_known && r.ips_known.length ? ` (해석된 IP ${r.ips_known.join(", ")} 이미 허용됨)` : "");
          if (r.added) return `대상 ${r.host} 을(를) 인가 목록에 자동 추가했습니다.${ipNote} 빼려면 🛡 인가 대상 관리에서 제거하세요.`;
          if (r.existed) return `대상 ${r.host} 은(는) 이미 인가된 대상입니다.${ipNote}`;
          return null;
        })();
    if (msg && !authNotified[s.id]) {
      authNotified[s.id] = true;
      await pushAssistant(s.id, msg);
    }
  } catch (e) {
    if (!authNotified[s.id]) {
      authNotified[s.id] = true;
      await pushAssistant(s.id, `대상 자동 인가 실패: ${e} — 인가 범위는 엔진이 계속 강제합니다.`);
    }
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

// ── 진단 모드 헬퍼: 입력창 플레이스홀더 + 진단 목표 반영 ──────────────────────
function setDiagPlaceholder() {
  const ci = $("chatInput");
  if (!ci) return;
  ci.placeholder = ($("diagChk") && $("diagChk").checked)
    ? "서비스 설명을 넣으면 더 정밀하게 — 없어도 URL 만으로 실측 정찰 후 진단합니다"
    : "대상이 있으면 위에 host/URL 을 입력하세요 · 지시 예: \"하반기 합격자 목록을 파일로 뽑아줘\"";
}

// ── [진단] 원클릭: URL 만으로 자동 보안 진단 (취약점 + 대비 시나리오) ──────────
async function runDiagnose() {
  const s = cur(); if (!s) return;
  if (!s.host && !$("shHost").value.trim()) { alert("먼저 위에 진단할 host/URL 을 입력하세요."); return; }
  const dc = $("diagChk");
  if (dc) dc.checked = true;
  s.diag = true;
  setDiagPlaceholder();
  if (!activeProvider()) { showProviderModal(); return; }
  // 단순 URL 만 있어도 에이전트가 실측 정찰로 서비스를 파악해 리포트를 낸다 (P0).
  $("chatInput").value = "이 서비스의 보안 진단을 해줘 — 취약점, 실행 가능한 공격 시나리오, 대비해야 할 위협, 그리고 미리 막는 방법까지 리포트로 정리해줘.";
  await sendChat();
}

// ── 프로바이더: 연결된 것만 리스트에 노출, 미설정 시 모달 유도 ────────────────
// 엔진 레지스트리(redcell/src/providers/registry.ts)와 동일하게 유지한다.
const PROVIDER_CATALOG = [
  { name: "anthropic", kind: "anthropic", note: "Claude 공식 API", default_model: "claude-opus-5", envKeys: ["ANTHROPIC_OAUTH_TOKEN", "ANTHROPIC_API_KEY"], baseUrl: "https://api.anthropic.com/v1", needsBase: false },
  { name: "openai", kind: "openai-compat", note: "GPT 공식 API", default_model: "gpt-5.4", envKeys: ["OPENAI_API_KEY"], baseUrl: "https://api.openai.com/v1", needsBase: false },
  { name: "openrouter", kind: "openai-compat", note: "다수 모델 게이트웨이 — 무료 모델은 모델란에 :free 접미사(예: meta-llama/llama-3.3-70b-instruct:free)", default_model: "moonshotai/kimi-k2.6", envKeys: ["OPENROUTER_API_KEY"], baseUrl: "https://openrouter.ai/api/v1", needsBase: false },
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
  if (sel && sel.value) { const v = sel.value.trim(); return v === "mock" ? "" : v; }
  const s = cur();
  const v = (s && s.provider ? s.provider : settings.default_provider || "").trim();
  return v === "mock" ? "" : v;
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
  // custom/ollama(base URL 필요) 를 맨 위로 — 스크롤 없이 바로 보이게.
  const rank = { custom: 0, ollama: 1 };
  const catalog = [...PROVIDER_CATALOG].sort((a, b) => (rank[a.name] ?? 9) - (rank[b.name] ?? 9));
  el.innerHTML = catalog.map((p) => {
    const st = providerConnState(p);
    const keyLabel = p.name === "custom" ? "API Key" : (p.envKeys.length ? p.envKeys[p.envKeys.length - 1] : "");
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
  // 연결 여부와 무관하게 전부 표시 — custom 은 아직 연결 전이라도 선택할 수 있다.
  sel.innerHTML = `<option value="">(선택 안 함)</option>`
    + PROVIDER_CATALOG.map((p) => `<option value="${p.name}">${p.name}${providerConnected(p) ? " ✅" : " (미연결)"}</option>`).join("");
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
  try { list = await invoke("get_providers"); } catch { return; } // 브라우저 프리뷰 환경
  if (!Array.isArray(list)) return;
  envReadyMap = {};
  list.forEach((p) => { envReadyMap[p.name] = !!p.ready_env; });
  const connected = PROVIDER_CATALOG.filter(providerConnected);
  // 헤더 프로바이더 셀렉트: 연결된 것 + 현재 세션/기본값 유지(custom 등).
  const psel = $("shProvider");
  if (psel) {
    const prev = psel.value || ((cur() && cur().provider) || settings.default_provider || "");
    psel.innerHTML = `<option value="">— provider 선택 —</option>`
      + connected.map((p) => `<option value="${esc(p.name)}">${esc(p.name)} ✅</option>`).join("");
    if (prev && connected.some((p) => p.name === prev)) {
      psel.value = prev;
    } else if (prev) {
      psel.insertAdjacentHTML("beforeend", `<option value="${esc(prev)}">${esc(prev)} (저장됨)</option>`);
      psel.value = prev;
    }
  }
  const hint = $("providerHint");
  if (hint) {
    const names = connected.map((p) => p.name);
    hint.textContent = names.length
      ? `LLM 연결됨: ${names.join(", ")} — ⚙ 설정에서 변경할 수 있습니다.`
      : "LLM 프로바이더 미연결 — ⚙ 설정에서 API 키를 등록하세요.";
  }
}

// ── 뷰 전환 ──────────────────────────────────────────────────────────────────
function switchView(name) {
  document.querySelectorAll(".subtab").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  const live = $("view-live");
  if (live) live.classList.toggle("active", name === "live");
  const rv = $("view-results");
  if (rv) rv.classList.toggle("active", name === "results");
  if (name === "results") renderResults();
}

// ── 결과 탭: 에이전트가 만들어낸 마크다운을 렌더링해 보여준다 ──────────────────
// pi stdout 의 text_end 가 note 이벤트로 들어온다. [sys]/[pi-툴]/[오류]/[완료] 같은
// 하위 노트는 제외하고, 실제 답변(마크다운 결과)만 모아 순서대로 보여준다.
function resultDocs(s) {
  const out = [];
  const seen = new Set();
  let prevText = null; // text_end/message_end 이중 저장 등 연속 중복은 1개만
  for (const e of eventsOf(s)) {
    const t = (e.text || "").trim();
    if (!t) continue;
    if (/^\[(sys|pi-툴|오류|완료|인텔)\]/.test(t)) continue;
    if (/^대상 .*(인가|자동 추가)/.test(t)) continue;
    const key = e._seq != null ? e._seq : `t:${t.slice(0, 48)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (t === prevText) continue; // 같은 결과가 연속 2번 저장된 경우
    prevText = t;
    out.push({ seq: e._seq, ts: e._ts != null ? e._ts : e.ts, text: t });
  }
  return out;
}

function resultsTabActive() {
  const rv = $("view-results");
  return !!(rv && rv.classList.contains("active"));
}

// ── 진단 리포트 요약: 루트별 위험도·검증 상태를 한눈에 (왼쪽 상단 등급 헤더) ──
function reportStats(docs) {
  const sev = { "치명": 0, "높음": 0, "중간": 0, "낮음": 0 };
  const ver = { "실증": 0, "징후": 0, "가정": 0 };
  const roots = []; // { sev, ver } — 루트별 증거 기반 위험도 산정용
  let cur = null;
  for (const d of docs) {
    for (const raw of (d.text || "").split(/\r?\n/)) {
      const line = raw.trim();
      if (/^#{1,4}\s*루트\s*\d+/.test(line)) {
        const m = line.match(/\[(치명|높음|중간|낮음)\]/);
        const key = m ? m[1] : (line.match(/(치명|높음|중간|낮음)/) || [])[1];
        const sk = sev[key] != null ? key : "낮음";
        sev[sk]++;
        cur = { sev: sk, ver: "가정" };
        roots.push(cur);
        continue;
      }
      // 검증(실측/확인/재현) 라인의 [실증]/[징후]/[가정] 을 해당 루트의 증거 상태로 반영.
      const vm = line.match(/\[(실증|징후|가정)\]/);
      if (vm) {
        if (/검증|실측|확인|재현/.test(line) && cur) cur.ver = vm[1];
        ver[vm[1]]++;
      }
    }
  }
  // 등급 = 루트별 (위험도 가중치 × 증거 가중치) 평균. 증거가 강할수록 가까이 인정된다.
  const vw = { "실증": 1.0, "징후": 0.6, "가정": 0.35 };
  const sw = { "치명": 4, "높음": 3, "중간": 2, "낮음": 1 };
  const m = roots.length;
  const score = m ? roots.reduce((a, r) => a + sw[r.sev] * (vw[r.ver] || 0.35), 0) / m : 0;
  const grade =
    m === 0 ? { letter: "·", label: "분석 전", cls: "g-none" }
      : score >= 3.3 ? { letter: "F", label: "심각", cls: "g-f" }
      : score >= 2.7 ? { letter: "D", label: "위험", cls: "g-d" }
      : score >= 2.0 ? { letter: "C", label: "보통", cls: "g-c" }
      : score >= 1.3 ? { letter: "B", label: "양호", cls: "g-b" }
      : { letter: "A", label: "안전", cls: "g-a" };
  return { roots: m, sev, ver, score, grade };
}
function renderReportSummary(s, docs) {
  const top = $("reportSummary");
  if (!top) return;
  const isDiag = s && s.diag;
  if (!isDiag || !docs.length) { top.classList.add("hidden"); top.innerHTML = ""; return; }
  const st = reportStats(docs);
  const sevChip = (label, n, cls) =>
    `<span class="rs-chip ${cls}"><b>${n}</b> ${label}</span>`;
  top.innerHTML = `
    <div class="rs-card">
      <div class="rs-grade ${st.grade.cls}"><span class="rs-letter">${st.grade.letter}</span><div class="rs-grade-txt"><b>${st.grade.label}</b><span>위험도 등급</span></div></div>
      <div class="rs-mid">
        <div class="rs-title"><b>${st.roots}개</b> 공격 루트 발굴${isDiag ? " · 실측 증거 반영 등급" : ""}</div>
        <div class="rs-chips">
          ${sevChip("치명", st.sev["치명"], "c-crit")}
          ${sevChip("높음", st.sev["높음"], "c-high")}
          ${sevChip("중간", st.sev["중간"], "c-med")}
          ${sevChip("낮음", st.sev["낮음"], "c-low")}
        </div>
      </div>
      <div class="rs-verify">
        <span class="rs-vtitle">검증 상태</span>
        <span class="rs-vchip v-proof"><b>${st.ver["실증"]}</b> 실증</span>
        <span class="rs-vchip v-sig"><b>${st.ver["징후"]}</b> 징후</span>
        <span class="rs-vchip v-assume"><b>${st.ver["가정"]}</b> 가정</span>
      </div>
      <div class="rs-actions">
        <button id="rsCopy" class="rs-btn" title="리포트 전체를 클립보드에 복사">복사</button>
        <button id="rsExport" class="rs-btn primary" title="리포트를 Markdown(.md) 파일로 저장">MD 저장</button>
        <button id="rsExportHtml" class="rs-btn" title="리포트를 자체 완성형 HTML 파일로 저장">HTML 저장</button>
        <span id="rsExportStatus" class="rs-export-status"></span>
      </div>
      ${isDiag ? renderDiagNav(st) : ""}
    </div>`;
  top.classList.remove("hidden");
  const exp = $("rsExport");
  const cpy = $("rsCopy");
  const expH = $("rsExportHtml");
  if (exp) exp.onclick = async () => await exportReport(s);
  if (expH) expH.onclick = async () => await exportReport(s, true);
  if (cpy) cpy.onclick = async () => await copyReport(s);
  // 진단 루트 위험도 필터 내비
  document.querySelectorAll("#reportSummary [data-f]").forEach((chip) => {
    chip.onclick = () => {
      const v = chip.dataset.f;
      diagFilter = v === "ALL" ? null : (diagFilter && diagFilter.has(v) && diagFilter.size === 1 ? null : new Set(v === "ALL" ? [] : [v]));
      renderResults();
    };
  });
}

// 진단 결과 위험도 필터 내비(루트 카드처럼 카드 렌더/숨김)
function renderDiagNav(st) {
  const sevs = ["치명", "높음", "중간", "낮음"];
  const clsFor = { "치명": "crit", "높음": "high", "중간": "med", "낮음": "low" };
  const active = diagFilter;
  const chip = (lbl, v, cls) => {
    const on = v === "ALL" ? !active || !active.size : !!(active && active.has(v));
    return `<button class="rs-nav-chip ${cls}${on ? " on" : ""}" data-f="${v}">${lbl}</button>`;
  };
  return `<div class="rs-nav"><span class="rs-nav-label">루트 보기</span>
     ${chip("전체", "ALL", "n-all")}
     ${sevs.map((sv) => chip(sv, sv, "n-" + clsFor[sv])).join("")}
     <span class="rs-nav-count">${st.roots}개 루트</span></div>`;
}

// ── 보고서 내보내기/복사 ─────────────────────────────────────────────────────
// 자체 완성형 HTML 내보내기용 최소 스타일 — 검증 배지·공격 흐름·시뮬레이션(정적)까지 포함.
const EXPORT_CSS = `
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0d1116;color:#dbe4ee;font:14px/1.7 system-ui,'Apple SD Gothic Neo','Malgun Gothic',sans-serif}
.wrap{max-width:920px;margin:0 auto;padding:42px 30px 70px}
.cover{border:1px solid #20272f;background:linear-gradient(135deg,#171c24,#10141a);border-radius:16px;padding:22px 24px;margin-bottom:26px}
.brand{font-size:12px;letter-spacing:.6px;color:#8f8dff;font-weight:700;margin-bottom:10px}
.cover h1{margin:0;font-size:23px;color:#fff}
.meta{color:#8a94a3;font-size:12.5px;margin-top:8px}
.md-body h1,.md-body h2,.md-body h3,.md-body h4,.md-body h5,.md-body h6{color:#eaf1f8;line-height:1.35}
.md-body h1,.md-body h2{border-bottom:1px solid #232a34;padding-bottom:7px;margin:26px 0 12px}
.md-body h3{margin:20px 0 8px}
.md-body h3{font-size:16px}
.md-body p{margin:9px 0}
.md-body ul,.md-body ol{margin:9px 0;padding-left:24px}
.md-body li{margin:4px 0}
.md-body code{font-family:'JetBrains Mono',Consolas,monospace;font-size:12.5px;background:rgba(255,70,85,.12);color:#ff9aa4;border-radius:5px;padding:1.5px 6px}
.md-body pre{background:#0b0f14;border:1px solid #232a34;border-radius:10px;padding:13px 15px;overflow-x:auto;margin:12px 0}
.md-body pre code{background:none;color:#c9d1d9;padding:0}
.md-body table{border-collapse:collapse;width:100%;margin:12px 0;font-size:13px}
.md-body th,.md-body td{border:1px solid #232a34;padding:7px 11px;text-align:left;vertical-align:top}
.md-body th{background:rgba(255,70,85,.07);font-weight:600}
.md-body tr:nth-child(even) td{background:rgba(255,255,255,.02)}
.md-body blockquote{border-left:3px solid #2b3240;margin:10px 0;padding:4px 14px;color:#9aa5b3;background:rgba(255,255,255,.02);border-radius:0 8px 8px 0}
.md-body hr{border:none;border-top:1px dashed #232a34;margin:16px 0}
.md-body a{color:#8f8dff}
.badge{display:inline-block;font-size:10.5px;font-weight:700;padding:1.5px 8px;border-radius:999px;margin:0 2px}
.bx-crit{background:rgba(255,93,93,.18);color:#ff8f8f}
.bx-high{background:rgba(255,142,77,.18);color:#ffb777}
.bx-med{background:rgba(242,177,52,.18);color:#ffd073}
.bx-low{background:rgba(93,212,142,.18);color:#7fe0a9}
.bx-info{background:rgba(142,168,255,.18);color:#8ab8ff}
.bx-assume{background:rgba(160,168,182,.18);color:#aab4c2}
.bx-proof{background:rgba(93,212,142,.2);color:#7fe0a9;border:1px solid rgba(93,212,142,.4)}
.bx-sig{background:rgba(242,177,52,.2);color:#ffd073;border:1px solid rgba(242,177,52,.4)}
.bx-p{background:rgba(255,93,122,.16);color:#ff8da1}
.diag-flow{display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin:12px 0;padding:13px 15px;background:#131920;border:1px solid #232a34;border-radius:12px}
.diag-step{display:inline-flex;align-items:center;padding:5px 11px;border-radius:999px;font-size:12.5px;font-weight:600;background:rgba(255,255,255,.04);border:1px solid #2b3240;color:#dbe4ee}
.diag-step.vuln{background:rgba(255,93,93,.15);border-color:rgba(255,93,93,.45);color:#ff9aa4}
.diag-step.loss{background:rgba(242,177,52,.14);border-color:rgba(242,177,52,.45);color:#ffd073}
.diag-arrow{color:#8a94a3;font-size:12px;margin:0 3px}
.diag-field{display:flex;gap:10px;margin:8px 0;padding:8px 12px;border-radius:10px;background:rgba(255,255,255,.02)}
.diag-field .df-label{flex:none;font-size:11.5px;font-weight:700;color:#8a94a3;min-width:66px}
.diag-field.field-risk .df-label{color:#ff8f8f}
.diag-field.field-loss{background:rgba(242,177,52,.06);border:1px dashed rgba(242,177,52,.4)}
.diag-field.field-loss .df-label{color:#ffd073}
.diag-field.field-fix{background:rgba(93,212,142,.06);border:1px dashed rgba(93,212,142,.35)}
.diag-field.field-fix .df-label{color:#7fe0a9}
.diag-field.field-verify .df-label{color:#8f8dff}
.diag-field .df-body{display:inline-flex;flex-wrap:wrap;gap:5px;align-items:center;font-size:13px}
.dchip{display:inline-block;font-size:11.5px;padding:2px 10px;border-radius:999px;background:rgba(242,177,52,.14);border:1px solid rgba(242,177,52,.4);color:#ffd073;font-weight:600}
.verify-chip{margin-right:4px}
.sim{background:#131920;border:1px solid #232a34;border-radius:12px;margin:12px 0;overflow:hidden}
.sim-head{display:flex;align-items:center;gap:8px;padding:9px 13px;border-bottom:1px solid #232a34;background:#171c24;font-size:12.5px}
.sim-title b{color:#8f8dff}
.sim-ctl,.sim-track,.sim-prog,.sim-note{display:none}
.sim-steps{list-style:none;margin:0;padding:12px;display:grid;gap:10px}
.sim-step{display:flex;gap:9px;align-items:stretch;opacity:1!important;filter:none!important}
.sim-n{flex:none;width:20px;height:20px;margin-top:3px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;background:#222a34;border:1px solid #2b3240;color:#8a94a3}
.sim-row{display:flex;align-items:stretch;gap:8px;flex:1;min-width:0;flex-wrap:wrap}
.sim-bubble{flex:1 1 200px;min-width:170px;padding:9px 12px;border-radius:10px}
.sim-bubble.do{background:rgba(255,93,93,.09);border:1px solid rgba(255,93,93,.32)}
.sim-bubble.res{background:rgba(93,212,142,.08);border:1px solid rgba(93,212,142,.3)}
.sim-tag{display:block;font-size:10px;font-weight:700;letter-spacing:.4px;margin-bottom:5px}
.sim-bubble.do .sim-tag{color:#ff9aa4}
.sim-bubble.res .sim-tag{color:#7fe0a9}
.sim-txt{font-size:12.5px;line-height:1.55}
.sim-cap{display:block;margin-top:5px;font-size:10px;color:#8a94a3}
.sim-conn{flex:none;display:inline-flex;align-items:center;color:#8a94a3;font-size:15px;padding:0 1px}
@media (max-width:640px){.sim-row{display:grid}.sim-conn{display:none}}
`;

function diagToExportHtml(s, name) {
  const body = mdToHtml(reportMarkdown(s));
  const date = new Date().toLocaleString("ko-KR");
  const target = s && s.host ? escHtml(s.host + (s.port ? ":" + s.port : "")) : "(—)";
  const title = escHtml((name || "RedCell 진단 리포트").trim() || "RedCell 진단 리포트");
  return `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title><style>${EXPORT_CSS}</style></head>
<body><div class="wrap">
 <div class="cover">
   <div class="brand">🛡 RedCell · 보안 진단 리포트</div>
   <h1>${title}</h1>
   <div class="meta">대상 ${target} · 생성 ${date}</div>
 </div>
 <div class="md-body">${body}</div>
</div></body></html>`;
}

function reportMarkdown(s) {
  return resultDocs(s).map((d) => d.text).join("\n\n");
}

async function exportReport(s, asHtml) {
  const btn = $("rsExport");
  const btnH = $("rsExportHtml");
  const st = $("rsExportStatus");
  const target = asHtml ? btnH : btn;
  if (!target || !st) return;
  const name = ((s && (s.name || "redcell-report")) || "redcell-report").replace(/[^\w가-힣 -]/g, "").trim() || "redcell-report";
  target.disabled = true; st.textContent = "저장 중…";
  try {
    const content = asHtml ? diagToExportHtml(s, name) : reportMarkdown(s);
    const path = await invoke("write_report", { name, content, format: asHtml ? "html" : "md" });
    st.textContent = "💾 " + path;
    st.className = "rs-export-status ok";
  } catch (e) {
    st.textContent = "저장 실패: " + e;
    st.className = "rs-export-status err";
  } finally {
    target.disabled = false;
  }
}
async function copyReport(s) {
  const st = $("rsExportStatus");
  const md = reportMarkdown(s);
  const fallbackDone = () => { if (st) { st.textContent = "복사됨"; st.className = "rs-export-status ok"; } };
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(md);
      fallbackDone();
    } else {
      // WebView/구버전 폴백 — textarea 를 임시로 만들어 execCommand
      const ta = document.createElement("textarea");
      ta.value = md; document.body.appendChild(ta); ta.select();
      document.execCommand("copy"); document.body.removeChild(ta);
      fallbackDone();
    }
  } catch (e) {
    if (st) { st.textContent = "복사 실패"; st.className = "rs-export-status err"; }
  }
}

// ── 진단 리포트를 루트 카드로 분할 (prelude/루트/권고·실측) ──────────────────
const RISK_CLS = { "치명": "rk-crit", "높음": "rk-high", "중간": "rk-med", "낮음": "rk-low" };
function segmentDiag(docs) {
  const out = [];
  let pre = [];      // 첫 루트 앞(요약·범위·공격 표면)
  let tail = [];     // 마지막 루트 뒤(권고·실측 확인)
  let cur = null;    // 현재 루트 누적
  let seenRoot = false;
  const flushRoot = () => {
    if (cur) { out.push({ kind: "root", title: cur.title, sev: cur.sev, text: cur.buf.join("\n") }); cur = null; }
  };
  for (const d of docs) {
    for (const raw of (d.text || "").split(/\r?\n/)) {
      const isRoot = /^#{1,4}\s*루트\s*\d*\.?\s*/.test(raw.trim());
      // 루트 헤딩 → 새 루트 카드 시작
      if (isRoot) {
        if (pre.length && !seenRoot) { out.push({ kind: "prelude", title: "요약·범위·공격 표면", sev: null, text: pre.join("\n") }); pre = []; }
        flushRoot();
        seenRoot = true;
        const txt = raw.replace(/^#{1,4}\s*루트\s*\d*\.?\s*/, "").trim();
        const sevM = txt.match(/\[(치명|높음|중간|낮음)\]/);
        cur = { title: txt.replace(/\s*\[(치명|높음|중간|낮음)\]\s*/, "").trim(), sev: sevM ? sevM[1] : null, buf: [raw] };
        continue;
      }
      // 루트 중간에 '## 섹션' 시작 → 루트 마감, 이후는 tail(권고~)
      if (cur && /^##\s+/.test(raw.trim())) {
        flushRoot();
        tail.push(raw);
        continue;
      }
      if (cur) cur.buf.push(raw);
      else if (seenRoot) tail.push(raw);
      else pre.push(raw);
    }
  }
  flushRoot();
  if (tail.length) out.push({ kind: "tail", title: "권고·실측 확인", sev: null, text: tail.join("\n") });
  if (pre.length && !out.some((o) => o.kind === "prelude")) out.unshift({ kind: "prelude", title: "요약·범위·공격 표면", sev: null, text: pre.join("\n") });
  return out.filter((it) => it.text.trim());
}

function renderResults() {
  const s = cur();
  const el = $("resultsBody");
  const cnt = $("resultsCount");
  const docs = s ? resultDocs(s) : [];
  renderReportSummary(s, docs);
  if (cnt) { cnt.textContent = String(docs.length); cnt.style.display = docs.length ? "inline-flex" : "none"; }
  if (!el) return;
  // 재렌더 전 이전 플레이어의 재생 타이머 정리
  el.querySelectorAll("[data-sim]").forEach(simStop);
  if (!docs.length) {
    el.innerHTML = `<div class="placeholder">아직 표시할 결과가 없습니다.<br/>에이전트가 정리한 마크다운 결과가 여기에 렌더링되어 표시됩니다.</div>`;
    return;
  }

  // 진단 리포트: 루트별 카드로 분할 + 위험도 필터 (지정된 심각도만 루트 표시).
  let segs = (s && s.diag)
    ? segmentDiag(docs)
    : docs.map((d) => ({ kind: "doc", title: "", sev: null, text: d.text, seq: d.seq, ts: d.ts }));
  if (s && s.diag && diagFilter && diagFilter.size) {
    const fset = diagFilter;
    segs = segs.map((it) => (it.kind === "root" && fset.has(it.sev) ? it : it.kind === "root" ? null : it)).filter(Boolean);
  }
  el.innerHTML = segs.map((it) => {
    const isRoot = it.kind === "root";
    const rk = it.sev ? RISK_CLS[it.sev] || "" : "";
    const tag = isRoot ? `<span class="md-kind root">루트</span>`
      : it.kind === "prelude" ? `<span class="md-kind pre">요약·범위</span>`
      : it.kind === "tail" ? `<span class="md-kind tail">권고·실측</span>`
      : `<span class="md-kind doc">결과</span>`;
    const title = isRoot ? esc(it.title) : (it.seq != null ? `#${it.seq}` : (it.kind === "tail" ? "권고·실측 확인" : it.kind === "prelude" ? "요약·범위" : ""));
    return `<article class="md-card ${rk}${isRoot ? " is-root" : ""}">
       <header class="md-card-head">
         ${tag}<span class="md-card-title">${title}</span>
         <span class="md-card-ts">${hhmm(it.ts)}</span>
       </header>
       <div class="md-body">${mdToHtml(it.text)}</div>
     </article>`;
  }).join("");
  wireSimPlayers(el);
}

function escHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/* 미니 마크다운 → HTML (의존성 없음). 입력은 먼저 이스케이프한 뒤 변환하므로 안전. */
const DIAG_BADGES = { "치명": "bx-crit", "높음": "bx-high", "중간": "bx-med", "낮음": "bx-low", "정보": "bx-info", "가정": "bx-assume", "실증": "bx-proof", "징후": "bx-sig", "P0": "bx-p", "P1": "bx-p", "P2": "bx-p", "P3": "bx-p" };
function inlineMd(s) {
  s = s.replace(/`([^`]+)`/g, (_, c) => `<code>${c}</code>`);
  s = s.replace(/\[\s*(치명|높음|중간|낮음|정보|가정|실증|징후|P[0-3])\s*\]/g, (_, b) => `<span class="badge ${DIAG_BADGES[b]}">${b}</span>`);
  s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  s = s.replace(/\*([^*\s][^*]*)\*/g, "<em>$1</em>");
  s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (m, label, url) => {
    if (/^(javascript|data|vbscript):/i.test(url)) return m;
    return `<a href="${url}" target="_blank" rel="noreferrer">${label}</a>`;
  });
  return s;
}

/* 공격 흐름: "공격자 → 로그인 폼 → (SQL 주입) → 인증 우회 → (관리자 세션 탈취) → …" 을
   화살표 다이어그램(스텝 칩)으로 렌더. ( ) 안의 취약점 단계와 탈취 단계에 색을 입힌다. */
function diagFlowHtml(content) {
  const steps = content.split(/→|->|➜/g).map((s) => s.trim()).filter(Boolean);
  if (!steps.length) return "";
  const cls = (seg) => {
    const s = seg.toLowerCase();
    if (/탈취|유출|노출|열람|획득|도난|유실|탈취/.test(s)) return "loss";
    if (/주입|취약|우회|남용|위조|스머글|레이스|포이즈닝|삽입|오염|스캔|exploit|바이패스|탈취/.test(s)) return "vuln";
    return "step";
  };
  const html = steps.map((seg, i) => {
    const lbl = seg.replace(/^[(\[]|[)\]]$/g, "").trim();
    const arrow = i > 0 ? '<span class="diag-arrow">➜</span>' : "";
    return `${arrow}<span class="diag-step ${cls(seg)}">${escHtml(lbl)}</span>`;
  }).join("");
  return `<div class="diag-flow">${html}</div>`;
}

/* 진단 필드 라인: 위험도/진입점/탈취 정보/공격 방법/영향/보완/검증 → 라벨+값 행 */
const VERIFY_ST = [
  ["실증", "bx-proof", "✅ 실증 — 실제 확인"],
  ["징후", "bx-sig", "⚠️ 징후 — 부분 확인"],
  ["가정", "bx-assume", "❓ 가정 — 설명 기반 추론"],
];
function diagFieldHtml(label, content) {
  const l = label.trim();
  const cls = l.includes("탈취") ? "field-loss" : l === "위험도" ? "field-risk" : l.includes("보완") ? "field-fix" : l === "검증" ? "field-verify" : "";
  let body;
  if (l.includes("탈취")) {
    body = content.split(/[,，·、\/]/).map((s) => s.trim()).filter(Boolean)
      .map((s) => `<span class="dchip">${escHtml(s)}</span>`).join("");
  } else if (l === "검증") {
    // 검증 상태 마커: [실증]/[징후]/[가정] 또는 '실증 :'/'실증 —' 등 접두 — 없으면 일반 표기
    const mk = /^\s*[\[(]?(실증|징후|가정)[\])]?\s*[:：]?\s*/.exec(content);
    let chip = "";
    let rest = content;
    if (mk) {
      const m = VERIFY_ST.find((x) => x[0] === mk[1]);
      if (m) {
        chip = `<span class="badge ${m[1]} verify-chip">${m[2]}</span>`;
        rest = content.slice(mk[0].length);
      }
    }
    body = `${chip}<span>${inlineMd(escHtml(rest))}</span>`;
  } else {
    body = inlineMd(escHtml(content));
  }
  return `<div class="diag-field ${cls}"><span class="df-label">${l}</span><span class="df-body">${body}</span></div>`;
}

/* 시뮬레이션 파싱: "N. <행동> → <결과>" 줄들을 [행동, 결과] 쌍으로 */
function parseSimSteps(text) {
  const steps = [];
  for (const raw of text.split(/\n+/).map((s) => s.trim()).filter(Boolean)) {
    const line = raw.replace(/^\d+[.)]\s*/, "");
    const parts = line.split(/→|->|➜/g).map((s) => s.trim()).filter(Boolean);
    if (parts.length < 2) continue; // '→' 한 쌍(행동→결과)만 재생 단계로 삼는다
    steps.push({ do: parts[0], res: parts.slice(1).join(" → ") });
  }
  return steps;
}

/* 시뮬레이션 플레이어: "이렇게 하면 → 이렇게 된다" 를 단계별로 재생해 보여준다 */
function diagSimHtml(steps) {
  if (!steps.length) return "";
  const rows = steps.map((st, i) => `
    <li class="sim-step${i === 0 ? " on" : ""}" data-i="${i}">
      <span class="sim-n">${i + 1}</span>
      <div class="sim-row">
        <div class="sim-bubble do"><span class="sim-tag">공격자 행동</span><div class="sim-txt">${escHtml(st.do)}</div><span class="sim-cap">이렇게 하면</span></div>
        <span class="sim-conn">➜</span>
        <div class="sim-bubble res${st.res ? "" : " none"}"><span class="sim-tag">시스템 결과</span><div class="sim-txt">${st.res ? escHtml(st.res) : "(결과 미기재)"}</div><span class="sim-cap">이렇게 된다</span></div>
      </div>
    </li>`).join("");
  return `<div class="sim" data-sim data-cur="1" data-total="${steps.length}">
    <div class="sim-head">
      <span class="sim-title">🎬 단계 시뮬레이션 — <b>이렇게 하면 → 이렇게 된다</b></span>
      <span class="sim-ctl">
        <button class="sim-btn play" data-sim-act="play" title="전체 재생">▶ 재생</button>
        <button class="sim-btn" data-sim-act="step" title="다음 단계">+1 단계</button>
        <button class="sim-btn" data-sim-act="reset" title="처음부터">↺</button>
      </span>
      <span class="sim-prog">1/${steps.length}</span>
    </div>
    <div class="sim-track"><div class="sim-fill" style="width:${Math.round(100 / steps.length)}%"></div></div>
    <ol class="sim-steps">${rows}</ol>
    <div class="sim-note">이것은 실제 공격이 아닌 <b>예측 시나리오 시뮬레이션</b>입니다 — 아래 <b>검증 상태</b>([실증]/[징후]/[가정])로 실측 여부를 함께 확인하세요.</div>
  </div>`;
}

// ── 시뮬레이션 플레이어 상태/재생 ────────────────────────────────────────────
function simState(sim) {
  const total = Number(sim.dataset.total || 0);
  let cur = Number(sim.dataset.cur || 0);
  if (cur > total) cur = total;
  return { total, cur };
}
function renderSimState(sim) {
  const { total, cur } = simState(sim);
  sim.querySelectorAll(".sim-step").forEach((li) => {
    const i = Number(li.dataset.i);
    li.classList.toggle("on", i < cur);
    li.classList.toggle("now", i === cur - 1);
  });
  const fill = sim.querySelector(".sim-fill");
  if (fill) fill.style.width = `${Math.round((cur / total) * 100)}%`;
  const play = sim.querySelector('[data-sim-act="play"]');
  if (play) play.textContent = cur >= total ? "▶ 다시" : "▶ 재생";
  const prog = sim.querySelector(".sim-prog");
  if (prog) prog.textContent = `${cur}/${total}`;
}
function simStop(sim) { if (sim._timer) { clearInterval(sim._timer); sim._timer = null; } }
function simPlay(sim) {
  simStop(sim);
  const { total, cur } = simState(sim);
  if (cur >= total) sim.dataset.cur = "1";
  renderSimState(sim);
  sim._timer = setInterval(() => {
    const st = simState(sim);
    if (st.cur >= st.total) { simStop(sim); return; }
    sim.dataset.cur = String(st.cur + 1);
    renderSimState(sim);
  }, 950);
}
function simStepOnce(sim) {
  simStop(sim);
  const { total, cur } = simState(sim);
  sim.dataset.cur = String(cur >= total ? 1 : cur + 1);
  renderSimState(sim);
}
function simReset(sim) { simStop(sim); sim.dataset.cur = "1"; renderSimState(sim); }
function wireSimPlayers(root) {
  root.querySelectorAll("[data-sim]").forEach((sim) => renderSimState(sim));
}

function mdToHtml(src) {
  const lines = src.split(/\r?\n/);
  const out = [];
  let para = [];
  const flushPara = () => { if (para.length) { out.push(`<p>${inlineMd(para.join(" "))}</p>`); para = []; } };
  const splitRow = (r) => r.trim().replace(/^\||\|$/g, "").split("|").map((c) => inlineMd(c.trim()));
  const isSep = (r) => /^\s*\|[\s:|-]+\|\s*$/.test(r) && /-/.test(r);
  let i = 0;
  while (i < lines.length) {
    const raw = lines[i];
    // fenced code
    if (/^```|^~~~/.test(raw)) {
      flushPara();
      const buf = [];
      i++;
      while (i < lines.length && !/^(```|~~~)\s*$/.test(lines[i])) { buf.push(lines[i]); i++; }
      i++;
      out.push(`<pre><code>${escHtml(buf.join("\n"))}</code></pre>`);
      continue;
    }
    // pipe table
    if (/^\s*\|/.test(raw) && i + 1 < lines.length && isSep(lines[i + 1])) {
      flushPara();
      const rows = [raw];
      i += 2; // 헤더 + 구분선 소비
      while (i < lines.length && /^\s*\|/.test(lines[i])) { rows.push(lines[i]); i++; }
      let html = "<table><thead><tr>";
      for (const c of splitRow(rows[0])) html += `<th>${c}</th>`;
      html += "</tr></thead><tbody>";
      for (const r of rows.slice(1)) {
        if (!r.trim()) continue;
        html += "<tr>";
        for (const c of splitRow(r)) html += `<td>${c}</td>`;
        html += "</tr>";
      }
      html += "</tbody></table>";
      out.push(html);
      continue;
    }
    // 진단 필드 라인 (위험도:/진입점:/탈취 정보:/공격 방법:/영향:/보완:/검증:) — 들여쓰기 허용
    const fld = /^\s*(위험도|진입점|탈취\s*정보|공격\s*방법|영향|보완|검증|우선순위|문제)[:：]\s*(.*)$/.exec(raw);
    if (fld) {
      flushPara();
      const lines2 = [fld[2]];
      i++;
      while (i < lines.length && /^\s*(→|->|➜)/.test(lines[i])) { lines2.push(lines[i].trim()); i++; }
      if (fld[1].includes("흐름")) {
        out.push(diagFlowHtml(lines2.join(" ")));
      } else {
        out.push(diagFieldHtml(fld[1], lines2.join(" ")));
      }
      continue;
    }
    // 시뮬레이션 블록: '시뮬레이션:' 라벨 + 'N. 행동 → 결과' 번호 줄들 → 단계 재생 플레이어
    const simLbl = /^\s*시뮬레이션[:：]\s*(.*)$/.exec(raw);
    if (simLbl) {
      flushPara();
      const buf = [simLbl[1]];
      i++;
      while (i < lines.length) {
        const t = lines[i].trim();
        const hasArrow = /→|->|➜/.test(t);
        if (/^\d+[.)]\s+/.test(t) && hasArrow) { buf.push(t); i++; continue; }
        if (!buf[0] && hasArrow) { buf[0] = t; i++; continue; } // 라벨 뒤 첫 내용이 다음 줄이라면 흡수(화살표 있는 줄만)
        break;
      }
      const steps = parseSimSteps(buf.join("\n"));
      if (steps.length) out.push(diagSimHtml(steps));
      continue;
    }
    // 공격 흐름 라인 (연결 줄 포함)
    const flow = /^\s*공격\s*흐름[:：]\s*(.+)$/.exec(raw);
    if (flow) {
      flushPara();
      const lines2 = [flow[1]];
      i++;
      while (i < lines.length && /^\s*(→|->|➜)/.test(lines[i])) { lines2.push(lines[i].trim()); i++; }
      out.push(diagFlowHtml(lines2.join(" ")));
      continue;
    }
    const h = /^\s{0,3}(#{1,6})\s+(.*)$/.exec(raw);
    if (h) { flushPara(); const lv = h[1].length; out.push(`<h${lv}>${inlineMd(escHtml(h[2]))}</h${lv}>`); i++; continue; }
    if (/^\s*(-{3,}|\*{3,})\s*$/.test(raw)) { flushPara(); out.push("<hr/>"); i++; continue; }
    if (/^>\s?/.test(raw)) {
      flushPara();
      const buf = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) { buf.push(lines[i].replace(/^>\s?/, "")); i++; }
      out.push(`<blockquote>${inlineMd(escHtml(buf.join(" ")))}</blockquote>`);
      continue;
    }
    const ul = /^\s*[-*+]\s+(.*)$/.exec(raw);
    if (ul) {
      flushPara();
      const items = [ul[1]];
      i++;
      while (i < lines.length) { const m2 = /^\s*[-*+]\s+(.*)$/.exec(lines[i]); if (!m2) break; items.push(m2[1]); i++; }
      out.push(`<ul>${items.map((x) => `<li>${inlineMd(escHtml(x))}</li>`).join("")}</ul>`);
      continue;
    }
    const ol = /^\s*\d+[.)]\s+(.*)$/.exec(raw);
    if (ol) {
      flushPara();
      const items = [ol[1]];
      i++;
      while (i < lines.length) { const m2 = /^\s*\d+[.)]\s+(.*)$/.exec(lines[i]); if (!m2) break; items.push(m2[1]); i++; }
      out.push(`<ol>${items.map((x) => `<li>${inlineMd(escHtml(x))}</li>`).join("")}</ol>`);
      continue;
    }
    if (raw.trim() === "") { flushPara(); i++; continue; }
    para.push(escHtml(raw));
    i++;
  }
  flushPara();
  return out.join("\n");
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
  const c = (settings.providers || {}).custom || {};
  if (!c.base_url && !c.api_key) expandedProvider = "custom"; // 미연결 custom 은 펼쳐서 보여줌
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

// ── 진단 이력 대시보드 ───────────────────────────────────────────────────────
function dashSessionStats(s) {
  const base = { status: s.status, target: s.host + (s.port ? ":" + s.port : ""), updated: hhmm((s.updated_at) || Date.now()) };
  if (!s.diag) {
    const goal = (s.goal && s.goal.trim()) || "대화 · 일반 작업";
    return { ...base, kind: "work", goal: goal.length > 60 ? goal.slice(0, 60) + "…" : goal };
  }
  const docs = resultDocs(s);
  if (!docs.length) return { ...base, kind: "diag", pending: true };
  const st = reportStats(docs);
  return { ...base, kind: "diag", pending: false, roots: st.roots, sev: st.sev, ver: st.ver, grade: st.grade };
}
function renderDashboard() {
  const body = $("dashBody");
  if (!body) return;
  const ordered = [...sessions].sort((a, b) => (String(b.updated_at || "").localeCompare(String(a.updated_at || ""))));
  if (!ordered.length) {
    body.innerHTML = `<div class="dash-empty">아직 세션이 없습니다 — [새 세션]으로 시작하세요.</div>`;
    return;
  }
  body.innerHTML = ordered.map((s) => {
    const st = dashSessionStats(s);
    const statusCls = ["running", "done", "error", "stopped", "idle"].includes(st.status) ? st.status : "idle";
    let card;
    if (st.kind === "diag" && !st.pending) {
      card = `
        <div class="dash-grade ${st.grade.cls}"><b>${st.grade.letter}</b><span>${st.grade.label}</span></div>
        <div class="dash-main">
          <div class="dash-title"><b>${esc(st.target)}</b><span class="dash-status s-${statusCls}">${esc(st.status)}</span></div>
          <div class="dash-meta">루트 ${st.roots}개 · ${esc((s.name || "").trim() || "진단 세션")}</div>
          <div class="dash-chips">
            <span class="dc crit">치명 ${st.sev["치명"]}</span><span class="dc high">높음 ${st.sev["높음"]}</span>
            <span class="dc med">중간 ${st.sev["중간"]}</span><span class="dc low">낮음 ${st.sev["낮음"]}</span>
            <span class="dc v">실증 ${st.ver["실증"]} · 징후 ${st.ver["징후"]} · 가정 ${st.ver["가정"]}</span>
          </div>
        </div>`;
    } else if (st.kind === "diag") {
      card = `
        <div class="dash-grade g-none"><b>·</b><span>진단 중</span></div>
        <div class="dash-main"><div class="dash-title"><b>${esc(st.target)}</b><span class="dash-status s-${statusCls}">${esc(st.status)}</span></div>
        <div class="dash-meta">진단 리포트 미완성 · ${esc((s.goal && s.goal.slice(0,60)) || "대기")}</div></div>`;
    } else {
      card = `
        <div class="dash-grade g-none"><b>◇</b><span>작업</span></div>
        <div class="dash-main"><div class="dash-title"><b>${esc(st.target || "(대상 미지정)")}</b><span class="dash-status s-${statusCls}">${esc(st.status)}</span></div>
        <div class="dash-meta">${esc(st.goal)}</div></div>`;
    }
    return `<article class="dash-card" data-session="${s.id}">${card}
        <div class="dash-foot"><span class="dash-upd">${esc(st.updated)}</span>
          <button class="btn btn-ghost btn-xs dash-open">열기</button></div>
      </article>`;
  }).join("");
  // 카드 클릭 → 해당 세션 열기
  body.querySelectorAll("[data-session]").forEach((card) => {
    const sid = card.dataset.session;
    const open = () => { $("dashboardModal").classList.add("hidden"); selectSession(sid); };
    card.querySelector(".dash-open").onclick = open;
    card.onclick = (e) => { if (!e.target.closest(".dash-open")) open(); };
  });
}
function openDashboard() { renderDashboard(); $("dashboardModal").classList.remove("hidden"); }

// ── 배선 ─────────────────────────────────────────────────────────────────────
function wire() {
  $("newSessionBtn").onclick = newSession;
  $("emptyNewBtn").onclick = newSession;
  $("settingsBtn").onclick = openSettings;
  $("dashboardBtn").onclick = openDashboard;
  $("dashboardClose").onclick = () => $("dashboardModal").classList.add("hidden");
  $("settingsCancel").onclick = () => $("settingsModal").classList.add("hidden");
  $("settingsClose").onclick = () => $("settingsModal").classList.add("hidden");
  $("settingsSave").onclick = saveSettings;
  $("providerGoto").onclick = () => { $("providerModal").classList.add("hidden"); openSettings(); };
  $("providerClose").onclick = () => $("providerModal").classList.add("hidden");
  wireProviderCards();
  // 모달 공통: 바깥 클릭 / Esc 로 닫기
  ["settingsModal", "authModal", "providerModal", "dashboardModal"].forEach((id) => {
    const m = $(id);
    if (!m) return;
    m.addEventListener("pointerdown", (e) => { if (e.target === m) m.classList.add("hidden"); });
  });
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    ["settingsModal", "authModal", "providerModal", "dashboardModal"].forEach((id) => { const m = $(id); if (m && !m.classList.contains("hidden")) m.classList.add("hidden"); });
  });
  $("runBtn").onclick = onRunButton;
  $("diagBtn").onclick = runDiagnose;
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
  ["shName", "shHost", "shPort", "shProvider"].forEach((id) => $(id) && $(id).addEventListener("change", () => persistHeader()));
  const diagChk = $("diagChk");
  if (diagChk) diagChk.addEventListener("change", () => {
    const s = cur();
    if (s) s.diag = diagChk.checked;
    persistHeader();
    setDiagPlaceholder();
  });
  document.querySelectorAll(".subtab").forEach((btn) => { btn.onclick = () => switchView(btn.dataset.view); });
  // 시뮬레이션 플레이어 컨트롤 (결과 탭 전체 위임 — 재렌더 후에도 유지)
  const rb = $("resultsBody");
  if (rb) rb.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-sim-act]");
    if (!btn) return;
    const sim = btn.closest("[data-sim]");
    if (!sim) return;
    const act = btn.dataset.simAct;
    if (act === "play") simPlay(sim);
    else if (act === "step") simStepOnce(sim);
    else if (act === "reset") simReset(sim);
  });
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
