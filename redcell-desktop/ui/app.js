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
let resultsSegs = []; // 현재 렌더 중인 결과 카드별 원문 (개별 내보내기용)
const reportSeenCounts = {}; // 세션별 확인한 리포트 수 — 새로 도착하면 결과 탭으로 자동 전환

const PHASE_ORDER = ["recon", "enumerate", "exploit", "post"];

const $ = (id) => document.getElementById(id);
const cur = () => sessions.find((s) => s.id === activeId) || null;
// get_session(전체) 결과를 sessions 배열에 반영하고 "전체 로드됨" 표시를 남긴다.
// list_sessions 는 요약(이벤트·채팅 제외)만 주므로, 전체가 필요한 화면은
// 이 표시를 보고 필요한 세션만 로드한다(ensureAllFull).
function applySession(fresh) {
  if (!fresh) return null;
  fresh.__full = true;
  const i = sessions.findIndex((x) => x.id === fresh.id);
  if (i >= 0) sessions[i] = fresh;
  return fresh;
}
async function ensureAllFull() {
  const need = sessions.filter((s) => !s.__full);
  if (!need.length) return;
  const results = await Promise.all(need.map((s) => invoke("get_session", { id: s.id }).catch(() => null)));
  results.forEach((fresh) => applySession(fresh));
}
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const clock = (ms) => { try { return new Date(ms).toLocaleTimeString("en-GB", { hour12: false }); } catch { return ""; } };
const hhmm = (ts) => {
  if (ts == null) return "";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit" });
};

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
  const phase = friendlyPhase(e.phase);
  const toolRaw = e.tool || (e.type === "finding" && e.finding ? e.finding.phase : "") || "";
  const tool = !toolRaw ? "—" : (e.tool ? toolLabel(e.tool) : friendlyPhase(toolRaw));
  const toolAttr = (toolRaw && toolRaw !== tool) ? ` title="${esc(toolRaw)}"` : "";
  const msg = e.text || (e.finding ? e.finding.title : "") || JSON.stringify(e);
  let status = "";
  if (e.type === "finding") status = e.finding ? e.finding.severity : "info";
  else if (e.type === "tool_result") status = e.ok ? "ok" : "fail";
  else if (e.type === "blocked") status = "blocked";
  else if (e.type === "error") status = "error";
  else if (e.type === "authorized" || e.type === "done") status = "ok";
  return { seq, time, phase, tool, toolAttr, msg, status, type: e.type || "note", sev: e.finding ? e.finding.severity : (e.severity || "") };
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
    <td class="c-tool"${f.toolAttr}>${esc(f.tool)}</td>
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
    tab.innerHTML = `<span class="tdot ${s.status}"></span><span class="tname">${esc(s.name)}</span><span class="tclose" title="닫기"><svg class="ic"><use href="#i-x"/></svg></span>`;
    tab.querySelector(".tname").onclick = () => selectSession(s.id);
    tab.querySelector(".tdot").onclick = () => selectSession(s.id);
    tab.querySelector(".tclose").onclick = (e) => { e.stopPropagation(); removeSession(s.id); };
    nav.appendChild(tab);
  }
}

// ── 렌더: 활성 세션 전체 ─────────────────────────────────────────────────────
function renderActive() {
  syncHero();
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
    // 이전 세션의 임시 항목 제거 (세션 전환 시 (저장됨) 잔류 방지).
    psel.querySelectorAll("option[data-temp]").forEach((o) => o.remove());
    const want = s.provider || settings.default_provider || "";
    const clean = want === "mock" ? "" : want; // 레거시 mock 값은 선택지로 삼지 않음
    if (clean && ![...psel.options].some((o) => o.value === clean)) {
      psel.insertAdjacentHTML("beforeend", `<option value="${esc(clean)}" data-temp="1">${esc(clean)} (저장됨)</option>`);
    }
    psel.value = clean;
  }
  const esel = $("shEngine");
  if (esel) esel.value = s.engine === "prime" ? "prime" : "pi";
  if ($("shCookie")) $("shCookie").value = s.auth_cookie || "";
  syncEngineSelects();
  const chatInput = $("chatInput");
  if (chatInput) {
    chatInput.placeholder = (s && s.diag)
      ? "예: 우리 쇼핑몰은 로그인·주문·결제 기능이 있어요 (없어도 주소만으로 진단합니다)"
      : "위에 주소를 입력하세요 · 예: \"사용할 수 있는 API 목록 찾아서 보여줘\"  ·  \"진단/점검\" 요청은 표준 진단으로 진행합니다";
  }
  setBadge(s.status);
  renderDangerBtn(s);
  loadMem();

  renderCapture(s);
  renderStepper(s);
  renderMetrics(s);
  renderFindings(s);
  renderIntel(s);
  renderNext(s);
  renderChat();
  renderDetail(null);
}

// ── 위험 검사 동의 ────────────────────────────────────────────────────────────
function renderDangerBtn(s) {
  const btn = $("dangerBtn");
  const label = $("dangerLabel");
  if (!btn || !label) return;
  const armed = !!(s && s.danger_consent);
  btn.classList.toggle("armed", armed);
  label.textContent = armed ? "위험 검사: 켜짐" : "위험 검사: 꺼짐";
  btn.title = armed
    ? `위험 검사 동의됨${s.danger_consented_at ? " (" + s.danger_consented_at + ")" : ""} — 클릭하면 즉시 끄기`
    : "위험 검사 — 사이트에 영향을 줄 수 있어 꺼져 있습니다 (자세한 설명 보기)";
}
let pendingDangerRetry = null; // 동의 후 재시도할 실행 (취소 시 파기)
function parseConsentError(e) {
  const s = String((e && e.message) || e || "");
  const i = s.indexOf("CONSENT_REQUIRED:");
  if (i < 0) return null;
  try { return JSON.parse(s.slice(i + "CONSENT_REQUIRED:".length)); } catch { return { level: "high", level_ko: "위험", concerns: [], summary: "위험한 작업으로 판단됨", shutdown_risk: false, data_loss_risk: false, irreversible: false }; }
}
function openDangerModal() {
  const s = cur();
  if (!s) return;
  pendingDangerRetry = null;
  $("dangerTitle").textContent = "위험 검사 동의";
  $("dangerTarget").textContent = s.host ? `${s.host}${s.port ? ":" + s.port : ""}` : "(주소 없음)";
  $("dangerStatic").classList.remove("hidden");
  $("dangerDynamic").classList.add("hidden");
  $("dangerAck").checked = false;
  $("dangerConfirm").disabled = true;
  $("dangerModal").classList.remove("hidden");
}
// 동적 위험 모달 — 백엔드 risk 평가를 표시하고 동의 시 retry() 재시도.
function openRiskModal(risk, retry) {
  const s = cur();
  if (!s) return;
  pendingDangerRetry = retry || null;
  $("dangerTitle").textContent = "위험한 작업 확인";
  $("dangerTarget").textContent = s.host ? `${s.host}${s.port ? ":" + s.port : ""}` : "(주소 없음)";
  $("dangerStatic").classList.add("hidden");
  $("dangerDynamic").classList.remove("hidden");
  const lv = $("riskLevel");
  lv.textContent = risk.level_ko || risk.level || "위험";
  lv.className = "risk-level " + (risk.level === "critical" ? "critical" : "high");
  $("riskSummary").textContent = risk.summary || "";
  const flags = [];
  flags.push(risk.shutdown_risk ? `<span class="risk-flag">서비스 중단 가능</span>` : `<span class="risk-flag ok">서비스 중단 없음</span>`);
  flags.push(risk.data_loss_risk ? `<span class="risk-flag">데이터 손실 가능</span>` : `<span class="risk-flag ok">데이터 손실 없음</span>`);
  flags.push(risk.irreversible ? `<span class="risk-flag">되돌릴 수 없음</span>` : `<span class="risk-flag ok">복구 가능</span>`);
  $("riskFlags").innerHTML = flags.join("");
  $("riskConcerns").innerHTML = (risk.concerns || []).map((c) =>
    `<li><b>${esc(c.title)}</b> — ${esc(c.impact)} <span class="danger-risk">근거: <span class="risk-match">${esc(c.matched)}</span> · ${c.reversible ? "되돌릴 수 있음" : "되돌릴 수 없음"}</span></li>`
  ).join("") || `<li>상세 근거 없음 — 내용을 다시 확인하세요.</li>`;
  $("dangerAck").checked = false;
  $("dangerConfirm").disabled = true;
  $("dangerModal").classList.remove("hidden");
}
async function cancelDangerPending(note) {
  pendingDangerRetry = null;
  const s = cur();
  if (note && s) {
    await invoke("append_chat", { id: s.id, role: "system", content: "위험한 작업은 보류했습니다 — 동의 없이 실행하지 않았습니다." });
    const fresh = await invoke("get_session", { id: s.id });
    if (fresh) { applySession(fresh); }
    renderChat();
  }
}
async function onDangerButton() {
  const s = cur();
  if (!s) return;
  if (s.danger_consent) {
    // 철회는 즉시 (안전한 방향 — 모달 없음).
    const upd = await invoke("set_danger_consent", { id: s.id, consent: false });
    if (upd) { const i = sessions.findIndex((x) => x.id === s.id); sessions[i] = upd; renderActive(); }
    return;
  }
  openDangerModal();
}
async function confirmDanger() {
  const s = cur();
  if (!s || !$("dangerAck").checked) return;
  const retry = pendingDangerRetry;
  pendingDangerRetry = null;
  const upd = await invoke("set_danger_consent", { id: s.id, consent: true });
  $("dangerModal").classList.add("hidden");
  if (upd) { const i = sessions.findIndex((x) => x.id === s.id); sessions[i] = upd; renderActive(); }
  if (retry) { try { await retry(); } catch (e) { console.error(e); } }
}

const STATUS_KO = { idle: "대기", running: "실행 중", done: "완료", error: "오류", stopped: "중지됨" };
function setBadge(status) {
  const b = $("statusBadge");
  b.textContent = STATUS_KO[status] || status;
  b.dataset.status = status;
  b.className = "badge badge-" + status;
  const running = status === "running";
  // 단일 액션 버튼(진단 시작)이 실행 중이면 '중지'로 뒤집힌다. 실행/중지 직관만 노출한다.
  const dbtn = $("diagBtn");
  if (dbtn) {
    dbtn.disabled = false;
    dbtn.dataset.mode = running ? "stop" : "diag";
    dbtn.classList.toggle("btn-stop", running);
    dbtn.classList.toggle("btn-diag", !running);
    dbtn.title = running ? "실행 중지 — 진행 중인 진단/작업을 멈춥니다" : "진단 시작 — 주소만 넣으면 결과 리포트를 자동으로 만듭니다";
    const dlabel = $("diagLabel");
    if (dlabel) dlabel.textContent = running ? "중지" : "진단 시작";
    const dic = $("diagIcon");
    if (dic) dic.innerHTML = '<use href="#' + (running ? "i-stop" : "i-crosshair") + '"/>';
  }
  const state = $("agentState");
  state.textContent = running ? "작동 중" : (status === "done" ? "완료" : status === "error" ? "오류" : status === "stopped" ? "중지됨" : "대기");
  state.className = "agent-state" + (running ? " busy" : "");
  const actEl = $("activityText");
  if (running && actEl) {
    // 재렌더/재시작 직후 문구가 비었으면 마지막 이벤트에서 복원한다.
    let t = actEl.textContent;
    if (!t) {
      const s = cur();
      const evs = s ? eventsOf(s) : [];
      const last = [...evs].reverse().find((e) => activityLine(e));
      t = withRound(s, (last && activityLine(last)) || "살펴보는 중…");
    }
    setActivity(t);
  }
  else hideActivity();
}

// ── 캡처 테이블 ──────────────────────────────────────────────────────────────
// ── 쉬운말 매핑: 표·상세의 단계/도구/유형을 사람 말로 ──────────────────────────
const PHASE_FRIENDLY = { recon: "정찰", enumerate: "수집", exploit: "검증", post: "정리" };
function friendlyPhase(p) { return (p && PHASE_FRIENDLY[p]) || p || "—"; }
const EV_FRIENDLY = { finding: "발견", action: "실행", tool_result: "도구 결과", phase: "단계", note: "기록", done: "완료", blocked: "차단", error: "오류", authorized: "인가 확인", distilled: "학습 저장", text_end: "리포트", worker_status: "작업 상태" };

// ── 라이브 필터 ───────────────────────────────────────────────────────────────
let liveFilter = "all";
function rowPassesFilter(e) {
  if (liveFilter === "all") return true;
  if (liveFilter === "finding") return e.type === "finding";
  if (liveFilter === "alert") return e.type === "blocked" || e.type === "error";
  return true;
}

// ── 꼬리 따라가기: 바닥 근처에서만 자동 스크롤 ────────────────────────────────
let tailFollow = true;
function syncTailBtn() {
  const btn = $("tailBtn"); const cap = document.querySelector(".capture");
  if (!btn || !cap) return;
  tailFollow = (cap.scrollHeight - cap.scrollTop - cap.clientHeight) < 40;
  btn.classList.toggle("hidden", tailFollow);
}
function scrollCaptureBottom() {
  const cap = document.querySelector(".capture");
  if (!cap) return;
  cap.scrollTop = cap.scrollHeight;
  tailFollow = true;
  const btn = $("tailBtn"); if (btn) btn.classList.add("hidden");
}

// ── 토스트: 흐름을 막는 alert() 대신 벗어나지 않는 알림 ───────────────────────
let toastTimer = null;
function toast(msg) {
  const el = $("toast");
  if (!el) return;
  el.textContent = msg;
  el.classList.remove("show");
  void el.offsetWidth; // 애니메이션 재시작
  el.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 3600);
}

// ── 채팅 미니 마크다운: 어시스턴트 답변 구조화(코드펜스·인라인·개행) ─────────
function chatHtml(content) {
  resetTermTips(); // 채팅 답변 하나 = 문서 하나
  const parts = esc(content).split("```");
  return parts.map((p, i) => (i % 2 === 1)
    ? `<pre class="chat-pre">${p.replace(/^\n+|\n+$/g, "")}</pre>`
    : inlineMd(p).replace(/\n/g, "<br>")).join("");
}

function syncSendBtn() {
  const ci = $("chatInput"), btn = $("chatSend");
  if (ci && btn) btn.disabled = !ci.value.trim();
}

// 실행 구분선 — 세션별 all 인덱스 배열. 재실행해도 기록은 유지하고 구분선만 꽂는다.
const runMarks = {};
function markRunStart(s) {
  if (!s) return;
  const n = eventsOf(s).filter((e) => e.type !== "worker_status").length;
  (runMarks[s.id] = runMarks[s.id] || []).push(n);
}
function renderCapture(s) {
  if (resultsTabActive()) renderResults();
  renderWorkerBar(s);
  const body = $("capBody");
  const all = eventsOf(s).filter((e) => e.type !== "worker_status"); // 워커 상태는 상단 칩으로
  const evs = all.filter(rowPassesFilter);
  const marks = new Set(runMarks[s.id] || []);
  let html = "";
  all.forEach((e, ai) => {
    if (!rowPassesFilter(e)) return;
    if (marks.has(ai)) html += `<tr class="run-sep"><td colspan="6">── 새 실행 ──</td></tr>`;
    html += rowHtml(e, ai);
  });
  body.innerHTML = html;
  const emptyEl = $("capEmpty");
  emptyEl.style.display = evs.length ? "none" : "block";
  emptyEl.textContent = (!evs.length && all.length)
    ? "조건에 맞는 기록이 없습니다 — 필터를 바꾸면 다시 볼 수 있습니다."
    : "대기 중 — 오른쪽 AI 도우미에게 말씀하시면 기록이 시작됩니다.";
  const cnt = $("liveFilterCount");
  if (cnt) cnt.textContent = `기록 ${evs.length}개`;
  wireRows();
  scrollCaptureBottom();
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
    : "대기 중 — 위에 주소를 입력하고 진단 시작을 누르면 진행 상황이 여기에 표시됩니다.";
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
  if (!ev) { el.innerHTML = `<div class="detail-empty">항목을 선택하면 자세한 내용이 표시됩니다.</div>`; return; }
  const row = (k, v) => `<div class="d-row"><span class="d-k">${esc(k)}</span><span class="d-v">${esc(v)}</span></div>`;
  let html = `<h4>${esc(EV_FRIENDLY[ev.type] || ev.type || "event")}</h4>`;
  if (ev.type === "finding" && ev.finding) {
    const f = ev.finding;
    html += row("severity", f.severity) + row("phase", friendlyPhase(f.phase)) + row("title", f.title);
    if (f.detail) html += `<pre>${esc(f.detail)}</pre>`;
    if (f.evidence) html += `<h4 style="margin-top:10px">evidence</h4><pre>${esc(f.evidence)}</pre>`;
  } else if (ev.type === "action") {
    html += row("tool", ev.tool ? toolLabel(ev.tool) : "—") + row("phase", friendlyPhase(ev.phase));
    if (ev.rationale) html += row("rationale", ev.rationale);
    // absolute-agent(pyrun): 에이전트가 스스로 작성한 파이썬 코드는 코드블록으로 보여준다.
    if (ev.tool === "python" && ev.args && typeof ev.args.code === "string") {
      html += `<h4 style="margin-top:10px">작성한 파이썬 코드</h4><pre class="code-block"><code>${esc(ev.args.code)}</code></pre>`;
    } else {
      html += `<h4 style="margin-top:10px">args</h4><pre>${esc(JSON.stringify(ev.args ?? {}, null, 2))}</pre>`;
    }
  } else if (ev.type === "tool_result") {
    html += row("tool", ev.tool ? toolLabel(ev.tool) : "—") + row("phase", friendlyPhase(ev.phase)) + row("ok", ev.ok ? "성공" : "실패") + (ev.severity ? row("severity", ev.severity) : "");
    if (ev.summary) html += `<pre>${esc(ev.summary)}</pre>`;
  } else {
    if (ev.phase) html += row("phase", friendlyPhase(ev.phase));
    html += `<pre>${esc(ev.text || "")}</pre>`;
  }
  html += `<details class="d-raw"><summary>원본 데이터</summary><pre>${esc(JSON.stringify(ev, null, 2))}</pre></details>`;
  el.innerHTML = html;
}

// ── 발견 ─────────────────────────────────────────────────────────────────────
function renderFindings(s) {
  const el = $("view-findings");
  if (!el) return;
  const fs = findingsOf(s);
  if (!fs.length) { el.innerHTML = `<div class="placeholder">아직 발견된 항목이 없습니다.<br/>오른쪽 AI 도우미에게 말씀해 보세요.</div>`; return; }
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
    [/sql|sqli/, "SQL 주입 신호 직접 확인", "탐지된 입력값에 오류 유발 문자를 넣어 보고 응답을 비교해 보세요. 확인할 때에는 최소한으로만 건드리세요."],
    [/openapi|swagger|api 명세|api-docs/, "API 설계도 노출 차단", "/openapi.json·/swagger 같은 설계도가 바깥에 열려 있으면 공격자가 전체 기능 지도를 얻습니다. 운영 환경에서는 로그인 뒤로 옮기거나 끄세요."],
    [/header|헤더|csp|hsts|x-frame/, "보안 헤더 보강", "빠진 CSP·HSTS·X-Frame-Options·X-Content-Type-Options·Referrer-Policy 를 추가하고 다시 점검해 확인하세요."],
    [/graphql/, "GraphQL 설계도 노출 확인", "운영 환경에서는 설계도 보기·테스트 화면을 끄고, 복잡한 질문에 제한을 두세요."],
    [/cors/, "CORS 허용 범위 줄이기", "모든 사이트(*)를 허용하는 설정을 지우고 필요한 주소만 허용하세요."],
    [/쿠키|cookie/, "로그인 쿠키 안전장치 설정", "HttpOnly·Secure·SameSite=Lax/Strict 를 켜세요. 꺼져 있으면 악성 스크립트나 도청으로 로그인이 가로채일 수 있습니다."],
    [/jwt/, "로그인 토큰(JWT) 검사 강화", "alg=none 거부·알고리즘 혼동(RS256↔HS256) 방지, 짧은 만료 시간, 토큰 안에 민감정보 넣지 않기."],
    [/secret|비밀|백업|\.env|credential|키/, "노출된 비밀번호·키 즉시 교체", "노출된 키·토큰·설정 파일은 새어 나간 것으로 보고 즉시 바꾼 뒤 접근 기록을 확인하세요."],
    [/upload|업로드/, "파일 올리기 검사 강화", "허용 확장자 목록, 저장 폴더 실행 금지, 파일명 새로 만들기, 크기 제한."],
    [/login|관리자|admin/, "관리자·로그인 페이지 보호", "기본 계정·쉬운 비밀번호를 바꾸고 2단계 인증·로그인 시도 제한·IP 허용 목록을 적용하세요."],
    [/열린 포트|port|ssh|redis|postgres|smb|mysql|3306|5432|6379/, "안 쓰는 문(포트) 닫기", "DB·캐시(5432/6379/3306) 같은 관리용 문이 바깥에 열려 있으면 방화벽으로 내부 전용으로 막으세요."],
    [/dir|경로|열거|enum/, "숨은 페이지 노출 확인", "찾아낸 주소들의 접근 권한·목록 공개 여부를 확인하고 필요 없는 노출은 막으세요."],
  ];
  for (const [re, t, d] of RULES) if (re.test(blob)) steps.push([t, d]);
  const fp = fingerprintOf(s);
  if (fp.service && fp.service !== "미상") steps.push([`${fp.service} 깊이 살펴보기`, "확인된 종류·버전을 기준으로 알려진 문제점을 좁혀 근거를 확보하세요."]);
  if (!steps.length) {
    const ran = eventsOf(s).some((e) => e.type === "tool_result");
    if (ran) steps.push(["범위 넓혀 다시 보기", "눈에 띄는 발견이 없었습니다. 주소·포트를 바꾸거나 다른 AI 모델로 다시 실행해 보세요."]);
    else steps.push(["아직 시작 전", "오른쪽 AI 도우미에게 하고 싶은 일을 말씀하세요. 주소는 점검 대상에 등록되어 있어야 합니다."]);
  }
  const blocked = eventsOf(s).filter((e) => e.type === "blocked");
  if (blocked.length) steps.push(["멈춘 동작 확인", `허용 범위를 벗어난 동작 ${blocked.length}건을 멈췄습니다. 점검 대상 목록을 확인하세요.`]);
  return steps;
}
function renderNext(s) {
  const el = $("view-next");
  if (!el) return;
  el.innerHTML = nextSteps(s).map(([t, d], i) =>
    `<div class="next-item"><div class="num">${i + 1}</div><div class="body"><b>${esc(t)}</b><br/><span>${esc(d)}</span></div></div>`).join("");
}

// ── 진단 후 '자동 보완': 다음 조치를 1클릭으로 에이전트에 지시 (LLM 재진단) ──────
function renderNextActions(s) {
  const steps = nextSteps(s);
  if (!steps.length) return "";
  const items = steps.map(([t, d], i) => `
    <div class="ns-card">
      <span class="ns-num">${i + 1}</span>
      <div class="ns-body"><b>${esc(t)}</b><p>${esc(d)}</p></div>
      <button class="ns-run" data-goal="${esc(t)} · ${esc(d)}" title="이 항목을 AI 도우미에게 시켜 실행·확인">실행<svg class="ic"><use href="#i-send"/></svg></button>
    </div>`).join("");
  return `<section class="next-actions">
    <header class="ns-title">
      <span class="ns-ico"><svg class="ic"><use href="#i-check"/></svg></span>
      <div><b>이어서 하기</b><span>아래 항목을 누르면 AI 도우미가 바로 실행·확인합니다</span></div>
    </header>
    <div class="ns-grid">${items}</div>
  </section>`;
}

// ── 대화 ─────────────────────────────────────────────────────────────────────
function renderChat() {
  const s = cur();
  const el = $("chatMessages");
  const chat = (s && s.chat) || [];
  if (!chat.length) { el.innerHTML = `<div class="placeholder">하고 싶은 일을 말씀하세요.<br/>AI가 방법을 찾아 왼쪽 진행 상황에서 보여줍니다.</div>`; return; }
  el.innerHTML = chat.map((m) => `<div class="msg ${m.role}">${m.role === "assistant" ? chatHtml(m.content) : esc(m.content)}<span class="ts">${hhmm(m.ts)}</span></div>`).join("");
  el.scrollTop = el.scrollHeight;
}

// ── 현재 활동(메인 패널 헤드라인): 지금 하는 일을 사람 말로 ──────────────────
// 툴 이름을 사람이 읽는 짧은 동작으로.
const TOOL_LABEL = {
  http_probe: "웹 응답 파악",
  header_audit: "보안 헤더 점검",
  waf_detect: "방어 장비(WAF) 확인",
  crawl: "링크·폼 따라다니며 수집",
  jwt_audit: "로그인 토큰(JWT) 뜯어보기",
  port_scan: "열린 문(포트) 찾기",
  dir_enum: "숨은 페이지 찾기",
  api_discover: "숨은 기능(API) 찾기",
  api_probe: "숨은 기능 정보 확인",
  cookie_audit: "로그인 쿠키 안전장치 확인",
  cors_audit: "다른 사이트 접근 허용(CORS) 확인",
  secret_scan: "숨은 비밀번호·백업 파일 찾기",
  graphql_probe: "GraphQL 설계도 노출 확인",
  csrf_audit: "위조 요청(CSRF) 방어 확인",
  upload_probe: "파일 올리기 제한 확인",
  sqli_probe: "SQL 주입 신호 찾기",
  xss_probe: "악성 스크립트 삽입(XSS) 확인",
  path_traversal: "엉뚱한 파일 접근 시도",
  open_redirect: "엉뚱한 사이트로 보내기 확인",
  ssrf_probe: "서버 속임수(SSRF) 신호 확인",
  idor_probe: "남의 정보 접근(IDOR) 점검",
  ssti_probe: "템플릿 조종(SSTI) 확인",
  cmdi_probe: "서버 명령어 삽입 확인",
  xxe_probe: "파일 빼내기(XXE) 시도 확인",
  web_fetch: "사이트 직접 열어 확인",
  recon_list: "들어갈 수 있는 곳 찾기",
};
function toolLabel(name) { return TOOL_LABEL[name] || name; }

// ── 진단 분야 쉬운 이름: 백엔드는 W1·정찰 같은 내부 라벨을 보내므로 UI에서만 바꾼다 ──
const WORKER_FRIENDLY = {
  p0: { label: "기본 점검", title: "수백 가지 기본 항목을 자동으로 확인합니다" },
  w1: { label: "구조 살펴보기", title: "겉모습·메뉴·숨은 페이지를 찾습니다" },
  w2: { label: "입력값 점검", title: "입력창·검색창이 공격에 견디는지 봅니다" },
  w3: { label: "로그인·권한 점검", title: "로그인과 내 정보 보호를 확인합니다" },
  w4: { label: "정보 노출 점검", title: "숨은 파일·비밀번호 노출을 찾습니다" },
  w5: { label: "기능 오용 점검", title: "할인·주문 같은 기능이 악용되는지 봅니다" },
};
function friendlyWorker(id, fallbackLabel) {
  const f = WORKER_FRIENDLY[id];
  return f ? f.label : (fallbackLabel || id || "점검");
}
function friendlyWorkerTitle(id, fallbackTitle) {
  const f = WORKER_FRIENDLY[id];
  return f ? f.title : (fallbackTitle || "");
}
// 노트 앞머리의 [W2·주입] 같은 백엔드 태그를 쉬운 이름으로 바꾼다.
// 새 백엔드는 쉬운 이름을 직접 보내므로 그대로 둔다.
function friendlyWorkerTag(tag) {
  const t = tag || "";
  if (Object.values(WORKER_FRIENDLY).some((f) => f.label === t)) return t;
  const m = /W([1-5])/.exec(t);
  if (m) {
    const f = WORKER_FRIENDLY["w" + m[1]];
    if (f) return f.label;
  }
  if (/^P0/.test(t)) return WORKER_FRIENDLY.p0.label;
  return tag;
}
// 새 형식 태그([구조 살펴보기] 등) 매칭용.
const FRIENDLY_TAG_ALT = Object.values(WORKER_FRIENDLY).map((f) => f.label).join("|");

function activityLine(e) {
  switch (e.type) {
    case "authorized": return "점검 대상 확인됨 — 살펴보기를 준비합니다";
    case "phase": return ({
      recon: "겉모습 살펴보는 중 — 사이트 구조를 파악합니다",
      enumerate: "메뉴·기능 목록 만드는 중",
      exploit: "빈틈이 진짜 뚫리는지 확인 중",
      post: "결과 정리 중",
    })[e.phase] || "살펴보는 중";
    case "action": return `${toolLabel(e.tool)} 확인 중` + (e.rationale ? ` — ${e.rationale}` : "");
    case "tool_result": return `${toolLabel(e.tool)} 결과 — ${e.summary || (e.ok ? "완료" : "실패")}`;
    case "finding": return e.finding ? `발견: ${e.finding.title}` : "발견";
    case "distilled": return `방법 저장 — ${e.title || ""}`;
    case "blocked": return `멈춤 — ${toolLabel(e.tool || "")} (허용 범위 밖)`;
    case "done": return "완료 — 결과를 정리했습니다";
    case "worker_status": return workerActivity(e);
    case "note": return noteActivity(e.text || "");
    default: return null;
  }
}
// 심층 진단 노트 → 현재 진행 문구. 구체 패턴부터 검사한다.
function noteActivity(t) {
  if (/모델 연결 확인 중/.test(t)) return "AI 모델 연결 확인 중…";
  if (/모델 연결 확인 완료/.test(t)) return "AI 모델 연결됨 — 진단을 시작합니다…";
  if (/기본 점검 시작/.test(t)) return "기본 점검 중… (수백 가지 항목 자동 확인)";
  if (/기본 점검 — 항목 \d+개/.test(t)) return "기본 점검 끝 — 다섯 가지 정밀 진단을 준비합니다…";
  if (/P0 자동 스윕 시작/.test(t)) return "기본 점검 중… (수백 가지 항목 자동 확인)"; // 구 문구 호환
  if (/P0 스윕.*프로브 \d+개/.test(t)) return "기본 점검 끝 — 다섯 가지 정밀 진단을 준비합니다…"; // 구 문구 호환
  if (/1차 확인 끝/.test(t)) return "1차 확인 끝 — 1차 리포트 만드는 중…";
  if (/1차 리포트를 만들지 못했습니다/.test(t)) return "1차 리포트를 만들지 못했습니다 — 추가 확인 뒤 다시 시도합니다";
  if (/1차 리포트 완성/.test(t)) return "1차 리포트 완성 — 추가 확인은 계속됩니다…";
  if (/최종 리포트를 만듭니다/.test(t)) return "최종 리포트 만드는 중…";
  if (/최종 리포트 완성/.test(t)) return "최종 리포트 완성 — 결과 리포트 탭에서 확인하세요";
  if (/추가 확인을 중단/.test(t)) return "추가 확인 중단 — 1차 리포트는 그대로 둡니다";
  if (/추가 확인을 마칩니다/.test(t)) return "추가 확인 끝 — 최종 리포트 만드는 중…";
  const mRound2 = t.match(/추가 확인 (\d+)차 시작/);
  if (mRound2) return `추가 확인 ${mRound2[1]}차 — 엇갈린 단서 확인 중…`;
  const mRound2End = t.match(/추가 확인 (\d+)차 끝/);
  if (mRound2End) return `추가 확인 ${mRound2End[1]}차 끝`;
  const mRound = t.match(/추적 라운드 (\d+) 시작/);
  if (mRound) return `추가 확인 ${mRound[1]}차 — 엇갈린 단서 확인 중…`; // 구 문구 호환
  const mRoundEnd = t.match(/추적 라운드 (\d+) 종료/);
  if (mRoundEnd) return `추가 확인 ${mRoundEnd[1]}차 완료`; // 구 문구 호환
  if (/수렴 — 추가 발견 없음/.test(t)) return "확인 끝 — 최종 정리 준비 중…"; // 구 문구 호환
  if (/collector 가 실사용진단리포트를 병합/.test(t)) return "최종 리포트 만드는 중…"; // 구 문구 호환
  if (/collector 가 최종/.test(t)) return "최종 리포트 만드는 중…"; // 구 문구 호환
  if (/실사용진단리포트 병합 완료/.test(t)) return "최종 리포트 완성 — 결과 리포트 탭에서 확인하세요"; // 구 문구 호환
  if (/리포트 병합 완료/.test(t)) return "리포트 완성 — 결과 리포트 탭에서 확인하세요";
  if (/1라운드 완료.*(조기 리포트|의심진단리포트)를 발행/.test(t)) return "1차 리포트 만드는 중…"; // 구 문구 호환
  if (/(1차 리포트|의심진단리포트) 발행 — 결과 탭/.test(t)) return "1차 리포트 완성 — 정밀 진단은 계속됩니다…"; // 구 문구 호환
  if (/백그라운드 추적 취소 — (1차 리포트|의심진단리포트)/.test(t)) return "추가 확인 중단 — 1차 리포트는 유지됩니다"; // 구 문구 호환
  if (/^\[(오류|완료|중지|차단|경고)\]/.test(t)) return t.replace(/\s+/g, " ").trim().slice(0, 100);
  // 툴 호출 시작: [W3·인증] [pi-툴] web_fetch {"url":"…"} → 확인 중
  let m = t.match(/^\[([^\]]+)\] \[(?:pi|prime)-툴\] (\S+)/);
  if (m) {
    const url = (t.match(/"url"\s*:\s*"([^"]+)"/) || [])[1] || "";
    let host = "";
    try { host = url ? new URL(url).hostname : ""; } catch (_) {}
    return `${friendlyWorkerTag(m[1])} 확인 중 — ${toolLabel(m[2])}${host ? " " + host : ""}…`;
  }
  if (/\[(?:pi|prime)-툴[✓✗]\]/.test(t)) return null; // 툴 완료줄은 너무 잦아 스킵
  // 분야 분석 텍스트: [입력값 점검] <첫머리> (구 형식 [W2·주입] 도 처리)
  m = t.match(new RegExp(`^\\[(${FRIENDLY_TAG_ALT})\\]\\s*([\\s\\S]{1,70})`))
    || t.match(/^\[(W\d·[^\]]+)\]\s*([\s\S]{1,70})/);
  if (m) return `${friendlyWorkerTag(m[1])} 살펴보는 중 — ${m[2].replace(/\s+/g, " ").trim()}…`;
  if (/^\[sys\]/.test(t)) return t.replace(/\s+/g, " ").trim().slice(0, 90);
  return null;
}
// 워커 상태 한 건 → "쉬운 이름 + 상태" 한 줄 문구.
function workerActivity(e) {
  const name = friendlyWorker(e.worker, e.label);
  if (e.state && e.state !== "running") return `${name} ${e.state === "done" ? "완료" : e.state === "error" ? "실패" : "중지됨"}`;
  return `${name} 살펴보는 중…`;
}
// 현재 진행 중인 진단 차수 — 활동 바·워커 바에 "1차 · …" 형태로 붙인다.
// 실행 중이 아니면 null. 구 형식(추적 라운드·P0 스윕) 노트도 읽는다.
function currentRoundLabel(s) {
  if (!s || s.status !== "running") return null;
  const evs = eventsOf(s);
  for (let i = evs.length - 1; i >= 0; i--) {
    const t = evs[i].text || "";
    if (!t) continue;
    let m = t.match(/추가 확인 (\d+)차 (?:시작|끝)/);
    if (m) return `추가 확인 ${m[1]}차`;
    m = t.match(/추적 라운드 (\d+) (?:시작|종료)/);
    if (m) return `추가 확인 ${m[1]}차`;
    if (/최종 리포트를 만듭니다|최종 리포트 완성|최종 리포트를 만들지 못했습니다|collector 가|실사용진단리포트|수렴|추가 확인을 마칩니다/.test(t)) return null;
    if (/1차 리포트를 만듭니다|1차 리포트 완성|1차 확인 끝|1차 리포트를 만들지 못했습니다|의심진단리포트/.test(t)) return null;
    if (/기본 점검 — 항목|P0 스윕.*프로브 \d+개/.test(t)) return "1차";
    if (/기본 점검 시작|P0 자동 스윕 시작/.test(t)) return "기본 점검";
    if (/진단 시작 — 기본 점검 후|심층 진단 시작\(/.test(t)) return "1차";
  }
  return null;
}
function withRound(s, line) {
  const r = currentRoundLabel(s);
  if (!r || line.startsWith(r)) return line; // 차수 안내 노트는 이미 차수를 말한다
  return `${r} · ${line}`;
}
let runStartedAt = 0, elapsedTimer = null;
function setActivity(text) {
  const bar = $("activityBar"); if (!bar || !text) return;
  $("activityText").textContent = text;
  if (!runStartedAt) { runStartedAt = Date.now(); startElapsedTick(); }
  tickElapsed();
  bar.classList.remove("hidden");
}
function hideActivity() {
  const b = $("activityBar"); if (b) b.classList.add("hidden");
  runStartedAt = 0;
  if (elapsedTimer) { clearInterval(elapsedTimer); elapsedTimer = null; }
}
function startElapsedTick() {
  if (elapsedTimer) clearInterval(elapsedTimer);
  elapsedTimer = setInterval(tickElapsed, 1000);
}
function tickElapsed() {
  const el = $("activityElapsed"); if (!el || !runStartedAt) return;
  const s = Math.floor((Date.now() - runStartedAt) / 1000);
  el.textContent = `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
}

// ── 대화창 마일스톤: 결과·추가요청만 assistant 메시지로 ──────────────────────
function milestoneChat(e) {
  if (e.type === "finding" && e.finding) {
    const f = e.finding;
    return `발견 · [${(f.severity || "info").toUpperCase()}] ${f.title}` + (f.detail ? `\n${f.detail}` : "");
  }
  if (e.type === "blocked") {
    return `허용되지 않은 동작이라 멈췄습니다: ${toolLabel(e.tool || "")}.\n계속하려면 점검 대상 목록에 주소를 추가한 뒤 다시 실행하세요.`;
  }
  if (e.type === "error") return `실행 중 오류가 발생했습니다: ${e.text || ""}`.trim();
  return null;
}
async function pushAssistant(id, content) {
  await invoke("append_chat", { id, role: "assistant", content });
  const fresh = await invoke("get_session", { id });
  applySession(fresh);
  if (id === activeId) renderChat();
}

// ── 심층 진단 워커 보드: 워커별 최신 상태를 칩으로 ──────────────────────────────
function workerStates(s) {
  const st = {};
  for (const e of eventsOf(s)) {
    if (e.type === "worker_status" && e.worker) {
      st[e.worker] = { id: e.worker, state: e.state || "running", title: e.title || "", label: e.label || e.worker };
    }
  }
  return st;
}
function renderWorkerBar(s) {
  const bar = $("workerBar"); if (!bar) return;
  const st = s ? workerStates(s) : {};
  const order = ["p0", "w1", "w2", "w3", "w4", "w5"].filter((id) => st[id]);
  if (!order.length) { bar.classList.add("hidden"); bar.innerHTML = ""; return; }
  bar.classList.remove("hidden");
  const round = currentRoundLabel(s);
  bar.innerHTML = `<span class="wk-title">정밀 진단${round ? ` · ${esc(round)}` : ""}</span>` + order.map((id) => {
    const w = st[id];
    const dot = w.state === "done" ? "ok" : w.state === "error" ? "err" : w.state === "stopped" ? "stop" : "run";
    const txt = w.state === "done" ? "완료" : w.state === "error" ? "실패" : w.state === "stopped" ? "중지" : "진행 중";
    return `<span class="wk-chip ${dot}" title="${esc(friendlyWorkerTitle(id, w.title))}"><i></i>${esc(friendlyWorker(id, w.label))}<em>${txt}</em></span>`;
  }).join("");
}

// ── 라이브 이벤트 반영 ───────────────────────────────────────────────────────
function onLiveEvent(event) {
  const s = cur(); if (!s) return;
  if (event.type === "worker_status") { // 칩 갱신 + 활동 바에 진행 중 요약
    renderWorkerBar(s);
    const running = Object.values(workerStates(s)).filter((w) => w.state === "running");
    if (running.length === 1) setActivity(withRound(s, `${friendlyWorker(running[0].id, running[0].label)} 살펴보는 중…`));
    else if (running.length > 1) setActivity(withRound(s, `${friendlyWorker(running[0].id, running[0].label)} 등 ${running.length}곳을 함께 살펴보는 중…`));
    else { const line = activityLine(event); if (line) setActivity(withRound(s, line)); }
    return;
  }
  if (rowPassesFilter(event)) {
    const body = $("capBody");
    $("capEmpty").style.display = "none";
    const seq = event._seq != null ? event._seq : eventsOf(s).length - 1;
    // 증분 추가 경로에서도 실행 구분선을 꽂는다 (이벤트는 이미 push된 상태).
    const ai = eventsOf(s).filter((e) => e.type !== "worker_status").length - 1;
    if ((runMarks[s.id] || []).includes(ai)) {
      body.insertAdjacentHTML("beforeend", `<tr class="run-sep"><td colspan="6">── 새 실행 ──</td></tr>`);
    }
    body.insertAdjacentHTML("beforeend", rowHtml(event, seq));
    const lastTr = body.lastElementChild;
    if (lastTr) lastTr.onclick = () => {
      selectedSeq = parseInt(lastTr.dataset.seq, 10);
      document.querySelectorAll("#capBody tr").forEach((x) => x.classList.remove("sel"));
      lastTr.classList.add("sel");
      renderDetail(event);
    };
    const cnt = $("liveFilterCount");
    if (cnt) cnt.textContent = `기록 ${$("capBody").children.length}개`;
    if (tailFollow) scrollCaptureBottom();
  }

  // pi CLI 화면(터미널)으로 동일 이벤트를 스트리밍.
  if (s) renderPiConsole(s);
  if (resultsTabActive()) renderResults();
  else { // 라이브 탭 시청 중에도 리포트 도착을 뱃지로 알린다.
    const c = $("resultsCount");
    if (c && s) { const n = resultDocs(s).length; c.textContent = String(n); c.style.display = n ? "inline-flex" : "none"; }
    // 병합 리포트(report 표식)가 도착하면 결과 리포트 탭으로 자동 전환 —
    // 1차 리포트를 기다리지 않고 바로 보여주기 위함. (경고·중간 메모·일반 작업 제외)
    if (s.diag && event.report && (event.type === "note" || event.type === "text_end")) {
      const n = resultDocs(s).length;
      if (n > (reportSeenCounts[s.id] || 0)) {
        reportSeenCounts[s.id] = n;
        switchView("results");
        if (s.status === "running") {
          pushAssistant(s.id, event.report === "final"
            ? "최종 리포트가 나왔습니다 — 결과 리포트 탭에서 확인하세요."
            : "1차 리포트가 나왔습니다 — 결과 리포트 탭에서 확인하세요. 추가 확인은 뒤에서 계속됩니다.");
        }
      }
    }
  }

  renderStepper(s);
  renderMetrics(s);
  if (event.type === "finding") renderFindings(s);
  if (event.type === "done") { renderFindings(s); renderIntel(s); renderNext(s); }

  // 메인 패널 헤드라인 갱신 + 결과/요청은 대화창으로
  const line = activityLine(event);
  if (line) setActivity(withRound(s, line));
  const ms = milestoneChat(event);
  if (ms) pushAssistant(s.id, ms);
  if (event.type === "done") hideActivity();
}

// 실행 중 들어온 채팅 지시 대기열 — 세션별 1건(최신). onFinished 에서 이어서 실행한다.
const pendingGoals = {};
async function onFinished(id, status) {
  const fresh = await invoke("get_session", { id });
  applySession(fresh);
  const s = sessions.find((x) => x.id === id);
  const queued = pendingGoals[id];
  if (queued) {
    delete pendingGoals[id];
    await invoke("append_chat", { id, role: "assistant", content: `앞서 메모한 내용으로 이어서 실행합니다: "${queued}"` });
    const upd0 = await invoke("get_session", { id });
    applySession(upd0);
    if (id === activeId) { renderChat(); }
    try {
      markRunStart(sessions.find((x) => x.id === id));
      if (s && s.deep) await invoke("start_deep_diagnosis", { id });
      else await invoke("start_engagement", { id });
    } catch (e) {
      await invoke("append_chat", { id, role: "system", content: "이어서 실행 실패: " + e });
    }
    const upd1 = await invoke("get_session", { id });
    applySession(upd1);
    if (id === activeId) { renderChat(); renderTabs(); renderActive(); }
    return;
  }
  {
    const summary = status === "error"
      ? "실행 중 오류가 발생했습니다. 진행 상황 탭의 기록을 확인하세요."
      : (s && s.deep)
        ? "진단 완료 — 결과 리포트 탭에서 뚫리는 과정·증거·막는 방법을 확인하세요. 이어서 질문하면 같은 작업에서 답변합니다."
        : "완료 — 아래 입력창에서 이어서 말씀하세요(같은 작업으로 이어집니다).";
    await invoke("append_chat", { id, role: "assistant", content: summary });
  }
  const upd = await invoke("get_session", { id });
  applySession(upd);
  if (id === activeId) { renderChat(); renderNext(cur()); renderStepper(cur()); }
}

// ── 액션 ─────────────────────────────────────────────────────────────────────
async function selectSession(id) {
  activeId = id;
  const fresh = await invoke("get_session", { id });
  applySession(fresh);
  renderTabs();
  renderActive();
  switchView("live");
}

async function newSession() {
  const s = await invoke("create_session", { name: "", host: "127.0.0.1", port: null, goal: "", provider: settings.default_provider || "", mode: "tools", max: false, diag: false });
  sessions.unshift(s);
  if (s) s.__full = true;
  activeId = s.id;
  renderTabs();
  renderActive();
  $("shHost").focus();
}

async function removeSession(id) {
  if (!confirm("이 작업을 삭제할까요? 저장된 기록도 함께 삭제됩니다.")) return;
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
    engine: $("shEngine") ? ($("shEngine").value === "prime" ? "prime" : "") : (s.engine || ""),
    auth_cookie: $("shCookie") ? $("shCookie").value : (s.auth_cookie || ""),
    diag: !!s.diag,
    mode: "prime", // 이 앱은 prime-agent(pi) 전용 셸이다
    max: false,
  };
  const updated = await invoke("update_session", payload);
  applySession(updated);
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
      ? `고급 설정 파일(YAML)을 사용 중이라 ${r.host} 을(를) 자동 등록하지 않았습니다. 점검 범위는 그대로 적용됩니다.`
      : (() => {
          const ipNote = (r.ips_added && r.ips_added.length)
            ? ` 함께 찾은 IP도 등록했습니다: ${r.ips_added.join(", ")}`
            : (r.ips_known && r.ips_known.length ? ` (함께 찾은 IP ${r.ips_known.join(", ")}는 이미 등록됨)` : "");
          if (r.added) return `${r.host} 을(를) 점검 대상에 자동 등록했습니다.${ipNote} 빼려면 점검 대상 관리에서 제거하세요.`;
          if (r.existed) return `${r.host} 은(는) 이미 등록된 주소입니다.${ipNote}`;
          return null;
        })();
    if (msg && !authNotified[s.id]) {
      authNotified[s.id] = true;
      await pushAssistant(s.id, msg);
    }
  } catch (e) {
    if (!authNotified[s.id]) {
      authNotified[s.id] = true;
      await pushAssistant(s.id, `대상 자동 등록 실패: ${e} — 점검 범위는 그대로 적용됩니다.`);
    }
  }
}

async function runEngagement() {
  const s = cur(); if (!s) return null;
  if (!s.host && !$("shHost").value.trim()) { toast("주소를 먼저 입력하세요."); return null; }
  await persistHeader();
  if (!activeProvider()) { showProviderModal(); return null; } // 미설정 → 모달로 설정 유도
  await ensureTargetAuthorized();
  try {
    setBadge("running");
    markRunStart(s);
    await invoke("start_engagement", { id: s.id });
    // 백엔드가 지시문을 '진단' 의도로 판단해 세션을 승격했을 수 있다 —
    // 결과 탭이 리포트를 받으려면 UI 쪽 diag/deep 플래그를 맞춰야 한다(판정은 백엔드가 한다).
    // 세션 객체 전체를 교체하면 스트리밍 중 도착한 이벤트가 유실될 수 있어 플래그만 갱신한다.
    const after = await invoke("get_session", { id: s.id }).catch(() => null);
    const live = sessions.find((x) => x.id === s.id);
    if (after && live) {
      live.diag = !!after.diag;
      live.deep = !!after.deep;
    }
    // 승격 이유 문구 — 백엔드 판정 결과(diag·deep 플래그)를 그대로 옮긴다.
    if (after && after.diag && !s.diag) {
      return (after.deep && !s.deep)
        ? "깊게/정밀 요청으로 판단해 심층 진단(다섯 가지 관점 병렬 + 최종 병합)으로 진행합니다 — 결과 리포트 탭에서 확인하세요."
        : "진단 요청으로 판단해 표준 진단(리포트 표준 + 자동 기본 점검)으로 진행합니다 — 결과 리포트 탭에서 확인하세요.";
    }
    return null;
  } catch (e) {
    const risk = parseConsentError(e);
    if (risk) { // 위험한 작업 — 에러가 아니라 동의 모달로 전환
      setBadge("idle");
      openRiskModal(risk, () => runEngagement());
      return;
    }
    setBadge("error");
    const msg = "실행 실패: " + e;
    await invoke("append_chat", { id: s.id, role: "system", content: msg });
    const fresh = await invoke("get_session", { id: s.id });
    applySession(fresh);
    renderChat();
    toast(msg); // 스폰 실패(전형적: Windows npx 문제, redcell 경로/의존성)를 즉시 알린다
    return null;
  }
}

async function stopEngagement() {
  const s = cur(); if (!s) return;
  try {
    await invoke("stop_engagement", { id: s.id });
  } catch (e) {
    // 이미 종료된 경우 등 — 실제 상태를 다시 읽어 버튼 표시를 맞춘다.
    try {
      const fresh = await invoke("get_session", { id: s.id });
      if (fresh) {
        applySession(fresh);
        if (fresh.id === activeId) setBadge(fresh.status);
        renderTabs();
      }
    } catch { /* 무시 */ }
  }
}

// 단일 액션(진단 시작) 버튼: 실행 중이면 '중지'로 동작, 아니면 진단 시작.
function onDiagButton() {
  const s = cur();
  if ($("diagBtn").dataset.mode === "stop" || (s && s.status === "running")) return stopEngagement();
  return runDiagnose();
}

async function sendChat() {
  const s = cur(); if (!s) return;
  const input = $("chatInput");
  const text = input.value.trim();
  if (!text) return;
  if (!activeProvider()) { showProviderModal(); return; } // 입력 보존 + 설정 유도
  input.value = "";
  syncSendBtn();
  await persistHeader({ goal: text });
  await invoke("append_chat", { id: s.id, role: "user", content: text });
  const host = $("shHost").value.trim();
  const port = $("shPort").value.trim();
  const provider = activeProvider();
  const target = host ? `${host}${port ? ":" + port : ""}` : "(주소 없음 — 위에 주소를 입력하세요)";
  let ack;
  if (s.status === "running") {
    pendingGoals[s.id] = text;
    ack = `"${text}" 을(를) 메모했습니다. 지금 실행 중인 작업이 끝나면 이 내용으로 다시 실행됩니다.`;
  } else {
    ack = `알겠습니다: "${text}"\n${target} · AI 모델 ${provider} 로 실행합니다 — 왼쪽 진행 상황에서 확인하세요.`;
  }
  await invoke("append_chat", { id: s.id, role: "assistant", content: ack });
  const fresh = await invoke("get_session", { id: s.id });
  applySession(fresh);
  renderChat();
  switchView("live");
  if (s.status !== "running") {
    const why = await runEngagement();
    // WHY 안내 — 백엔드가 진단으로 승격한 이유를 사용자에게 그대로 보여준다.
    if (why) await pushAssistant(s.id, why);
  }
}

// ── 진단 모드 헬퍼: 입력창 플레이스홀더 + 진단 목표 반영 ──────────────────────
function setDiagPlaceholder() {
  const ci = $("chatInput");
  if (!ci) return;
  const s = cur();
  ci.placeholder = (s && s.diag)
    ? "예: 우리 쇼핑몰은 로그인·주문·결제 기능이 있어요 (없어도 주소만으로 진단합니다)"
    : "위에 주소를 입력하세요 · 예: \"사용할 수 있는 API 목록 찾아서 보여줘\"  ·  \"진단/점검\" 요청은 표준 진단으로 진행합니다";
}

// ── [진단 시작] 원클릭: URL 만으로 심층 진단 (5개 분야 병렬 + 시나리오 리포트) ─
const DEFAULT_DIAG_GOAL = "이 서비스의 보안 진단을 해줘 — 어디가 뚫리는지, 어떻게 뚫리는지, 무엇을 조심해야 하는지, 그리고 미리 막는 방법까지 리포트로 정리해줘.";
function activeEngine() {
  const sel = $("shEngine");
  if (sel && sel.value) return sel.value === "prime" ? "prime" : "pi";
  const s = cur();
  return s && s.engine === "prime" ? "prime" : "pi";
}
async function beginDeepDiagnosis(s) {
  const goal = (s.goal || "").trim() || DEFAULT_DIAG_GOAL;
  await invoke("append_chat", { id: s.id, role: "user", content: goal });
  await invoke("append_chat", { id: s.id, role: "assistant", content: `진단 시작 — 먼저 기본 점검을 한 뒤 다섯 가지 관점에서 동시에 깊이 살펴보고, 하나의 결과 리포트로 정리합니다. 왼쪽에서 진행을 확인하세요.` });
  const fresh = await invoke("get_session", { id: s.id });
  applySession(fresh);
  renderChat();
  switchView("live");
  try {
    setBadge("running");
    markRunStart(s);
    await invoke("start_deep_diagnosis", { id: s.id });
  } catch (e) {
    const risk = parseConsentError(e);
    if (risk) { // 위험한 진단 목표 — 동의 모달로 전환 (채팅 중복 없이 재시도)
      setBadge("idle");
      const sid = s.id;
      openRiskModal(risk, async () => {
        setBadge("running");
        try {
          await invoke("start_deep_diagnosis", { id: sid });
        } catch (e2) {
          if (parseConsentError(e2)) { setBadge("idle"); return; }
          throw e2;
        }
      });
      return;
    }
    setBadge("error");
    const msg = "진단 실패: " + e;
    await invoke("append_chat", { id: s.id, role: "system", content: msg });
    const f2 = await invoke("get_session", { id: s.id });
    applySession(f2);
    renderChat();
    toast(msg);
  }
}
async function runDiagnose() {
  const s = cur(); if (!s) return;
  if (!s.host && !$("shHost").value.trim()) { toast("먼저 위에 진단할 주소를 입력하세요."); return; }
  await persistHeader();
  if (!activeProvider()) { showProviderModal(); return; } // 입력 보존 + 설정 유도
  const s2 = cur();
  const upd = await invoke("update_session", {
    id: s2.id, name: s2.name, host: s2.host, port: s2.port,
    goal: (s2.goal || "").trim() || DEFAULT_DIAG_GOAL,
    provider: activeProvider() || s2.provider || "", mode: "prime", diag: true, deep: true,
    engine: activeEngine() === "prime" ? "prime" : "",
  });
  if (upd) { const i = sessions.findIndex((x) => x.id === s2.id); if (i >= 0) sessions[i] = upd; }
  setDiagPlaceholder();
  await ensureTargetAuthorized();
  await beginDeepDiagnosis(cur());
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
  // 기본 내장 연결 — LGE Databricks AI Gateway MLflow Responses 엔드포인트.
  // keyLabel 이 있으면 API 키 입력칸을 렌더링한다(envKeys 없이 키만 지정하는 내장 연결용).
  { name: "lge-aigw", kind: "openai-compat", note: "LGE Databricks AI Gateway — Responses API (GLM 5.3 Flash)", default_model: "system.ai.glm-5-3-flash", envKeys: [], keyLabel: "Databricks 토큰", baseUrl: "https://lge-esdatapf.cloud.databricks.com/ai-gateway/mlflow/v1", needsBase: false },
  { name: "ollama", kind: "openai-compat", note: "로컬/원격 ollama 서버 (키 불필요)", default_model: "llama3.1", envKeys: [], baseUrl: "http://localhost:11434/v1", needsBase: true },
  { name: "custom", kind: "openai-compat", note: "임의 엔드포인트 — vLLM·LM Studio·원격 ollama·Databricks AI Gateway(Anthropic 방식)", default_model: "", envKeys: ["REDCELL_OPENAI_API_KEY"], baseUrl: "", needsBase: true },
];
let envReadyMap = {}; // get_providers 의 ready_env (시스템 환경변수 감지)
let expandedProvider = null;

// A4) 프로바이더 이름을 사람 말로 — 내부 이름(anthropic·openai…)은 화면에 내보내지 않는다.
const PROVIDER_LABEL = {
  anthropic: "Anthropic (권장)",
  openai: "OpenAI",
  openrouter: "OpenRouter (여러 모델)",
  "prime-inference": "Prime Intellect",
  groq: "Groq (고속)",
  cerebras: "Cerebras (초고속)",
  xai: "xAI (Grok)",
  deepseek: "DeepSeek",
  mistral: "Mistral AI",
  moonshotai: "Moonshot (Kimi)",
  zai: "Z.ai (GLM)",
  "lge-aigw": "사내 AI 게이트웨이",
  ollama: "직접 연결 (로컬 서버)",
  custom: "직접 연결",
};
function providerLabel(name) {
  return PROVIDER_LABEL[name] || name;
}

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
    api: c.api || "",
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
    const keyLabel = p.name === "custom" ? "API Key" : (p.envKeys.length ? p.envKeys[p.envKeys.length - 1] : (p.keyLabel || ""));
    const hasKeyField = p.envKeys.length > 0 || !!p.keyLabel;
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
        ${p.name === "custom" ? `<label class="fld"><span>API 방식</span>
          <select class="sh-input mono" data-f="api" style="width:100%">
            <option value=""${!st.api ? " selected" : ""}>OpenAI 호환 (/chat/completions)</option>
            <option value="openai-responses"${st.api === "openai-responses" ? " selected" : ""}>OpenAI Responses (Databricks MLflow 게이트웨이 등)</option>
            <option value="anthropic-messages"${st.api === "anthropic-messages" ? " selected" : ""}>Anthropic Messages (Databricks AI Gateway 등)</option>
          </select>
        </label>` : ""}
        ${p.needsBase ? `<label class="fld"><span>Base URL</span><input class="sh-input mono" data-f="base" value="${esc(st.base_url || p.baseUrl)}" placeholder="${basePlaceholder}" spellcheck="false" /></label>` : ""}
        ${hasKeyField ? `<label class="fld"><span>API 키 <span class="lbl-dim">(${keyLabel})</span></span>
          <span class="pcard-keyrow">
            <input class="sh-input mono" data-f="key" type="password" value="${esc(st.api_key)}" placeholder="${p.name === "custom" ? "sk-… 또는 !명령어 …" : (p.name === "lge-aigw" ? "Databricks 토큰을 붙여넣으세요 (터미널의 $DATABRICKS_TOKEN)" : "sk-…")}" spellcheck="false" autocomplete="off" />
            <button class="btn btn-icon" data-act="eye" title="표시/숨김" aria-label="키 표시/숨김"><svg class="ic"><use href="#i-eye"/></svg></button>
          </span>
        </label>` : ""}
        ${p.name === "custom" ? `<div class="pcard-howto"><b>ug claude 와 같은 연결(Databricks)</b> — API 방식 <b>Anthropic Messages</b>, Base URL <code>https://&lt;workspace&gt;/ai-gateway/anthropic</code>, 모델 <code>system.ai.claude-sonnet-5-5</code>, 키 <code>!ug auth-token --host &lt;workspace&gt; --profile &lt;프로필&gt;</code> (<code>!</code>로 시작하면 요청마다 토큰 자동 발급). Anthropic 테스트는 최소 1토큰을 사용합니다.</div>` : ""}
        ${p.name === "lge-aigw" ? `<div class="pcard-howto"><b>연결 방법</b> — 터미널에서 <code>ug auth-token</code> 의 출력(Databricks 토큰)을 복사해 위 API 키 칸에 붙여넣고 연결 저장을 누르세요. 토큰은 만료되면 다시 발급해 붙여넣으면 됩니다. Base URL·모델은 기본값을 그대로 써도 됩니다.</div>` : ""}
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
  return { api_key: q('[data-f="key"]'), base_url: q('[data-f="base"]'), model: q('[data-f="model"]'), api: q('[data-f="api"]') };
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
    const res = await invoke("test_provider", { provider: p.name, apiKey: v.api_key, baseUrl: v.base_url || p.baseUrl, api: v.api || null, model: v.model || null });
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
      if (v.api_key || v.base_url || v.model || v.api) providers[name] = v;
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
    psel.innerHTML = `<option value="">— AI 모델을 고르세요 —</option>`
      + connected.map((p) => `<option value="${esc(p.name)}">${esc(providerLabel(p.name))} ✅</option>`).join("");
    if (prev && connected.some((p) => p.name === prev)) {
      psel.value = prev;
    } else if (prev) {
      psel.insertAdjacentHTML("beforeend", `<option value="${esc(prev)}">${esc(providerLabel(prev))} (저장됨)</option>`);
      psel.value = prev;
    }
  }
  const hint = $("providerHint");
  if (hint) {
    const names = connected.map((p) => providerLabel(p.name));
    hint.textContent = names.length
      ? `AI 모델 연결됨: ${names.join(", ")} — ⚙ 설정에서 변경할 수 있습니다.`
      : "AI 모델 미연결 — ⚙ 설정에서 연결하세요.";
  }
  syncObProvider();
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
// 진단 리포트 H1 정규화 — "{세션}-{주소} {종별}"로 통일. 리포트형 H1이 없으면 그대로 둔다.
function normalizeReportTitle(text, s, report) {
  const re = /^#\s+.*리포트.*$/m;
  if (!re.test(text)) return text;
  const kind = report === "early" ? "1차 리포트" : report === "final" ? "최종 리포트" : "진단 리포트";
  const name = ((s && s.name) || "").trim();
  const tgt = sessionTarget(s);
  const head = name && tgt ? `${name}-${tgt}` : (tgt || name || "진단");
  return text.replace(re, `# ${head} ${kind}`);
}

// 리포트 H1 판별 — 스트리밍 조각(이어지는 뒷부분)과 새로 발행된 리포트를 구분한다.
function hasReportTitle(t) {
  return /^#\s+.*리포트.*$/m.test(t || "");
}

// 하위 노트는 제외하고, 실제 답변(마크다운 결과)만 모아 순서대로 보여준다.
function resultDocs(s) {
  const out = [];
  const workerFallback = []; // 병합 실패 시 분야별 발견이라도 보여준다
  const seen = new Set();
  let prevText = null; // text_end/message_end 이중 저장 등 연속 중복은 1개만
  for (const e of eventsOf(s)) {
    const t = (e.text || "").trim();
    if (!t) continue;
    if (/^\[(sys|pi-툴|prime-툴|오류|완료|인텔)\]/.test(t)) continue;
    if (/^대상 .*(인가|자동 추가)/.test(t)) continue;
    // 진단 세션은 진짜 리포트만: 병합 표식 문서 + 긴 정리 문서.
    // "pong" 같은 자질구레한 기록은 결과 탭에 올리지 않는다(진행 상황에는 남는다).
    if (s && s.diag && !e.worker && !e.report && t.length < 200) continue;
    const key = e._seq != null ? `s:${e._seq}` : `t:${t.length}:${t.slice(0, 64)}:${t.slice(-32)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (t === prevText) continue; // 같은 결과가 연속 2번 저장된 경우
    prevText = t;
    const doc = { seq: e._seq, ts: e._ts != null ? e._ts : e.ts, text: t, report: e.report || null, seqs: e._seq != null ? [e._seq] : [] };
    // 분야별 중간 발견(worker 표식)은 최종 리포트가 아니면 결과에서 제외.
    if (e.worker) { workerFallback.push(doc); continue; }
    // 같은 표식의 연속 조각(스트리밍 분할)은 하나로 합친다 — 뒷조각은 H1이 없다.
    // H1을 가진 새 발행(재실행 등)은 별도 문서로 유지한다.
    const last = out.length ? out[out.length - 1] : null;
    if (last && doc.report && last.report === doc.report && !hasReportTitle(doc.text)) {
      last.text += "\n\n" + doc.text;
      last.ts = doc.ts;
      if (doc.seq != null) last.seqs.push(doc.seq);
      continue;
    }
    // 진단 리포트 제목은 "{세션}-{주소} {종별}"로 통일 (후속 Q&A 오적용 방지: 진단 세션+리포트형 H1만).
    if (s && s.diag) doc.text = normalizeReportTitle(t, s, doc.report);
    out.push(doc);
  }
  if (!out.length) return workerFallback;
  // 진단 세션에 발행 리포트가 있으면 표식 문서만 결과로 인정한다 — 중간 메모·
  // 임시 정리 같은 태그 없는 기록이 리포트 통계·내보내기에 섞이지 않게 한다.
  // 표식이 하나도 없는 구 세션은 긴 문서를 그대로 쓴다(기존 동작).
  if (s && s.diag && out.some((d) => d.report)) return out.filter((d) => d.report);
  // 1차·최종 두 리포트는 모두 보여준다 (통계·내보내기는 최신 리포트 기준으로 별도 집계).
  return out;
}

// 통계·내보내기 집계 대상 — 최신 발행 리포트 1건(전 차수 취합본)만.
// 과거 리포트·후속 메모를 합치면 위험 수가 뻥튀기되고 내보내기가 로그 나열이 된다.
// 태그 없는 구 세션은 전체 집계(기존 동작).
function statsDocs(docs) {
  let li = -1;
  docs.forEach((d, i) => { if (d.report) li = i; });
  return li < 0 ? docs : docs.slice(li, li + 1);
}

function resultsTabActive() {
  const rv = $("view-results");
  return !!(rv && rv.classList.contains("active"));
}

// 루트 카드 헤딩 판별 — 통계(reportStats)와 분할(segmentDiag)이 같은 집합을 센다.
// (번호 없는 "### 루트. …" 변형도 루트로 인정한다.)
const ROOT_HEADING_RE = /^#{1,4}\s*루트\s*\d*\.?\s*/;

// 등급 산정 기준값 — 심각도(영향)와 검증(확신)은 서로 다른 축이다.
//   SEV_INDEX : 심각도만 봤을 때의 위험 지수(0~10)
//   VER_FACTOR: 직접 확인일수록 확신(가정일수록 낮게 반영)
const SEV_INDEX = { "치명": 10, "높음": 7.5, "중간": 5, "낮음": 2.5 };
const VER_FACTOR = { "실증": 1.0, "징후": 0.85, "가정": 0.7 };
const VER_RANK = { "실증": 3, "징후": 2, "가정": 1 };
const SEV_RANK = { "치명": 4, "높음": 3, "중간": 2, "낮음": 1 };

// 등급 판정 — 평균으로 묻지 않는다.
// "직접 확인된 치명 1건 + 추측 낮은 등급 5건"이 평균이면 '안전' 으로 나오는 사고를
// 막기 위해, 확인된 최악 findings 가 등급의 하한(floor)이 된다.
// C1) A 는 '발견 0건' 만 뜻한다 — 발견이 1건이라도 있으면 최소 B(양호).
//     (등급 라벨: A 이상 없음 / B 양호 / C 보통 / D 위험 / F 심각)
function gradeOf(roots) {
  if (!roots.length) {
    return { letter: "A", label: "이상 없음", cls: "g-a", why: "점검 범위 안에서 알려진 결함을 확인하지 못했습니다" };
  }
  const has = (sev, ver) => roots.some((r) => r.sev === sev && (!ver || r.ver === ver));
  if (has("치명", "실증")) {
    return { letter: "F", label: "심각", cls: "g-f", why: "직접 확인된 치명 취약점이 있습니다 — 즉시 조치 필요" };
  }
  if (has("치명")) {
    return { letter: "D", label: "위험", cls: "g-d", why: "치명으로 추정되는 경로가 있습니다 — 실측 재현으로 확정 필요" };
  }
  if (has("높음", "실증")) {
    return { letter: "D", label: "위험", cls: "g-d", why: "직접 확인된 위험 등급 취약점이 있습니다" };
  }
  if (has("높음")) {
    return { letter: "C", label: "보통", cls: "g-c", why: "위험 등급으로 추정되는 경로가 있습니다 — 실측 재현 필요" };
  }
  if (has("중간", "실증")) {
    return { letter: "C", label: "보통", cls: "g-c", why: "직접 확인된 중간 등급 취약점이 있습니다" };
  }
  if (has("중간") || has("낮음", "실증")) {
    return { letter: "B", label: "양호", cls: "g-b", why: "중간 이하 취약점만 확인됐습니다 — 방어 심층화 권고 수준" };
  }
  // C1) A 는 '발견 0건' 만 뜻한다 — 발견이 1건이라도 있으면 최소 B.
  // (낮음+가정 만으로는 '안전' 이 아니다 — 확인하지 못한 것이 확인되지 않은 것뿐이다.
  //  화면에 'A 안전' 과 '3개 발견' 이 동시에 뜨던 혼선을 없앤다.)
  return { letter: "B", label: "양호", cls: "g-b", why: "낮은 등급의 발견만 있습니다 — 즉시 조치보다 확인·보완이 먼저입니다" };
}

// ── 진단 리포트 요약: 루트별 위험도·검증 상태를 한눈에 (왼쪽 상단 등급 헤더) ──
function reportStats(docs) {
  const sev = { "치명": 0, "높음": 0, "중간": 0, "낮음": 0 };
  const ver = { "실증": 0, "징후": 0, "가정": 0 };
  const roots = []; // { sev, ver, title } — 루트별 위험도 산정용
  let cur = null;
  for (const d of docs) {
    for (const raw of (d.text || "").split(/\r?\n/)) {
      const line = raw.trim();
      if (ROOT_HEADING_RE.test(line)) {
        const m = line.match(/\[(치명|높음|중간|낮음)\]/);
        const key = m ? m[1] : (line.match(/(치명|높음|중간|낮음)/) || [])[1];
        const sk = sev[key] != null ? key : "낮음";
        sev[sk]++;
        const title = line
          .replace(ROOT_HEADING_RE, "")
          .replace(/\s*\[(치명|높음|중간|낮음)\]\s*/, "")
          .trim();
        cur = { sev: sk, ver: "가정", title, explicit: false };
        roots.push(cur);
        continue;
      }
      // 검증 상태 — '검증:' 라벨이 붙은 줄이 가장 신뢰할 만한 근거다.
      // (라벨 줄이 없으면 '실측·확인·재현' 어휘가 있는 줄을 보조 근거로 쓴다.
      //  라벨 줄을 먼저 찾았다면 뒤의 보조 근거로는 덮어쓰지 않는다 —
      //  '근거: [가정]' 같은 후속 줄이 확인 상태를 깎아내면 안 된다.)
      const vm = line.match(/\[(실증|징후|가정)\]/);
      if (!vm || !cur) continue;
      const explicit = /^\**\s*검증\s*[:：]/.test(line);
      if (explicit) {
        cur.ver = vm[1];
        cur.explicit = true;
      } else if (!cur.explicit && /검증|실측|확인|재현/.test(line)) {
        cur.ver = vm[1];
      }
    }
  }
  // 분석은 끝났는데 '루트 N' 헤딩이 없다면(리포트 포맷 편차) 본문의 [위험도] 배지만으로
  // 등급을 대체 산정한다. → 완료된 진단을 '분석 전'으로 보이지 않게 한다.
  if (!roots.length) {
    for (const d of docs) {
      for (const raw of (d.text || "").split(/\r?\n/)) {
        const re = /\[(치명|높음|중간|낮음)\]/g;
        let mm;
        while ((mm = re.exec(raw)) !== null) {
          sev[mm[1]]++;
          // 같은 줄에 검증 배지가 있으면 그 상태를, 없으면 '가정' 으로 둔다.
          const vm = raw.match(/\[(실증|징후|가정)\]/);
          roots.push({ sev: mm[1], ver: vm ? vm[1] : "가정", title: "", explicit: false });
        }
        const rv = /\[(실증|징후|가정)\]/g;
        let mv;
        while ((mv = rv.exec(raw)) !== null) ver[mv[1]]++;
      }
    }
  } else {
    // 검증 카운트는 루트별 확정 상태만 집계한다 — 본문 곳곳의 배지 언급(범위·
    // 권고·실측 절의 인용)을 합산하면 '직접 확인' 건수가 부풀려진다.
    for (const r of roots) ver[r.ver]++;
  }
  // 위험 지수 — 심각도 × 확신. 가장 위험한 루트가 지수를 결정한다(평균 아님).
  const score = roots.reduce((acc, r) => {
    const v = (SEV_INDEX[r.sev] || 0) * (VER_FACTOR[r.ver] || VER_FACTOR["가정"]);
    return Math.max(acc, v);
  }, 0);
  // 등급 = 규칙 기반 (확인된 치명·높음이 하한을 정한다).
  const grade = gradeOf(roots);
  // 가장 위험한 루트 — 요약 헤더에 이름을 단다(사건번호 대신 사람이 읽는 한 줄).
  let worst = null;
  for (const r of roots) {
    const k = (SEV_RANK[r.sev] || 0) * 10 + (VER_RANK[r.ver] || 1);
    if (!worst || k > worst.k) worst = { k, r };
  }
  return { roots: roots.length, sev, ver, score, grade, worst: worst ? worst.r : null };
}
// ── 리포트 요약 바: 얇은 한 줄(등급 · 위험 수 · 내보내기) + 접히는 서랍 ──
// 리포트 본문이 상단 요약에 가리지 않도록:
//   (1) 첫 줄은 항상 한 줄로 유지하고, 서랍(필터 · 바로가기 · 직접 확인 · 범례)은 접고 시작하며,
//   (2) [자세히]로 펼치거나 [접기]로 접을 수 있고,
//   (3) 스크롤하면 자동 접힘 — 단, 수동 펼침 고정은 맨 위로 돌아올 때까지 유지된다.
let summaryPinned = true;        // 첫 화면은 접힘(리포트 본문 우선) · [자세히]로 펼침 고정
let summaryManual = false;       // 수동 펼침 고정 — 스크롤 자동 접힘을 이긴다
let summaryTightWindow = false; // 창이 낮으면 위에서도 접힘 유지(본문 우선)
const SUMMARY_COLLAPSE_AT = 48; // 이만큼 스크롤하면 서랍 자동 접힘(px)
const SUMMARY_TIGHT_H = 420;    // 리포트 영역이 이보다 낮으면 접고 시작

function summaryCardEl() { return document.querySelector("#reportSummary .rs-card"); }

// 스크롤 위치에 맞춰 요약 접힘 상태를 맞춘다(자동/고정).
// 지금 접어야 하는지 판단: 고정값 → 스크롤 위치 → 짧은 창이 여부.
function summaryCollapsedNow() {
  if (summaryPinned != null) return summaryPinned;
  const body = $("resultsBody");
  if (body && body.scrollTop > SUMMARY_COLLAPSE_AT) return true;
  return summaryTightWindow;
}

function syncSummaryCollapse() {
  const card = summaryCardEl();
  if (!card) return;
  const collapsed = summaryCollapsedNow();
  card.classList.toggle("collapsed", collapsed);
  const t = card.querySelector(".rs-toggle");
  if (t) {
    t.textContent = collapsed ? "자세히" : "접기";
    t.setAttribute("aria-expanded", String(!collapsed));
  }
}

// 본문 스크롤 이벤트: 스크롤하면 자동 접힘 — 수동 펼침 고정은 맨 위 복귀까지 유지.
// 맨 위로 돌아오면 기본 상태(접힘)로 복원한다.
function onResultsScroll() {
  const body = $("resultsBody");
  if (!body) return;
  if (body.scrollTop <= 1) {
    summaryManual = false;
    summaryPinned = true;
  } else if (!summaryManual && summaryPinned === false) {
    summaryPinned = true;
  }
  syncSummaryCollapse();
}

// [접기]/[펼치기] — 사용자가 직접 고정(펼침 고정은 스크롤해도 유지).
function toggleSummary() {
  summaryPinned = !summaryCollapsedNow();
  summaryManual = !summaryPinned;
  syncSummaryCollapse();
}

// 요약의 '바로가기' → 해당 카드로 이동(본문 스크롤 테이너 안에서만 스크롤).
function gotoCardSeg(ix) {
  const el = document.querySelector(`#resultsBody .md-card[data-ix="${ix}"]`);
  const body = $("resultsBody");
  if (!el || !body) return;
  // 스크롤 컨테이너의 scrollTop  직접 계산해 옮긴다.
  // (WebKitGTK 에서는 중첩 스크롤러에 대한 scrollIntoView(smooth) 가 무시되는 경우가 있어
  //  Chromium 검사만으로는 잡히지 않는다 — 실기기 창에서 확인하며 고정한 경로다.)
  const top = el.getBoundingClientRect().top - body.getBoundingClientRect().top + body.scrollTop - 8;
  body.scrollTop = Math.max(0, top);
  el.classList.add("flash");
  setTimeout(() => el.classList.remove("flash"), 1200);
}

// ── B) "지금 해야 할 일" 파싱 ───────────────────────────────────────────────
// 리포트 본문의 권고 절에서 [P0]/[P1] 항목(또는 루트의 '보완:' 필드)을 최대 3개 뽑아
// "우선순위 · 문제 한줄 · 조치 한줄" 로 보여준다. 파싱에 실패하면 조용히 숨긴다.
const PRIO_BY_SEV = { "치명": "P0", "높음": "P1", "중간": "P2", "낮음": "P3" };
const SEV_ORDER = { "치명": 4, "높음": 3, "중간": 2, "낮음": 1 };

// 최신 발행 리포트 1건의 인덱스 (statsDocs 와 같은 기준).
function latestReportIndex(docs) {
  let li = -1;
  (docs || []).forEach((d, i) => { if (d.report) li = i; });
  return li;
}

// "## " 절 단위로 텍스트를 나눈다 (종류 판별은 sectionKind 와 동일 규칙).
function splitSections(text) {
  const out = [];
  let cur = null;
  for (const raw of String(text || "").split(/\r?\n/)) {
    const line = raw.trim();
    if (/^##\s+/.test(line)) {
      const title = line.replace(/^#{1,6}\s*/, "").trim();
      cur = { title, kind: sectionKind(title), lines: [] };
      out.push(cur);
      continue;
    }
    if (!cur) { cur = { title: "", kind: null, lines: [] }; out.push(cur); }
    cur.lines.push(raw);
  }
  return out;
}

// 첫 절(구분자 '—'/'·') 까지 = 문제 한줄.
function firstClause(text) {
  const t = String(text || "").trim();
  const m = /^([^—–·]+?)(?=\s+[—–]\s+|\s·\s|$)/.exec(t);
  return (m ? m[1] : t).trim();
}
// '보완:' (또는 '조치:'/'권고:') 뒤 값 = 조치 한줄.
function pickField(text, labels) {
  const t = String(text || "");
  for (const lb of labels) {
    const re = new RegExp(lb + "\\s*[:：]\\s*(.+?)(?=\\s·\\s|$)");
    const m = re.exec(t);
    if (m && m[1].trim()) return m[1].trim();
  }
  return "";
}
function pickSev(text) {
  const m = /위험도\s*\[?\s*(치명|높음|중간|낮음)/.exec(String(text || ""));
  return m ? m[1] : null;
}

// 루트 블록의 '보완:' 필드 (권고 절에 항목이 없을 때 대체 사용).
function parseRootFixes(text) {
  const out = [];
  let cur = null;
  for (const raw of String(text || "").split(/\r?\n/)) {
    const line = raw.trim();
    if (ROOT_HEADING_RE.test(line)) {
      if (cur && cur.fix) out.push(cur);
      const txt = line.replace(/^#{1,4}\s*루트\s*\d*\.?\s*/, "").trim();
      const sevM = txt.match(/\[(치명|높음|중간|낮음)\]/);
      cur = { title: txt.replace(/\s*\[(치명|높음|중간|낮음)\]\s*/, "").trim(), sev: sevM ? sevM[1] : null, fix: "" };
      continue;
    }
    if (!cur) continue;
    if (/^#{1,6}\s+/.test(line)) { if (cur.fix) out.push(cur); cur = null; continue; }
    const f = /^\s*보완\s*[:：]\s*(.+)$/.exec(line);
    if (f && !cur.fix) cur.fix = f[1].trim();
  }
  if (cur && cur.fix) out.push(cur);
  return out;
}

// 항목 → 대상 루트 카드 매칭 (제목 포함 관계 → 공통 접두사 → 위험도 일치 순).
function commonPrefixLen(a, b) {
  let n = 0;
  while (n < a.length && n < b.length && a[n] === b[n]) n++;
  return n;
}
function matchRoot(item, roots) {
  if (!roots.length) return null;
  const prob = item.problem.replace(/\s+/g, " ").trim();
  let best = null;
  for (const r of roots) {
    const t = (r.it.title || "").replace(/\s+/g, " ").trim();
    if (!t) continue;
    if (prob.indexOf(t) >= 0 || t.indexOf(prob) >= 0) {
      const len = Math.min(t.length, prob.length);
      if (!best || len > best.len) best = { r, len };
    }
  }
  if (best) return best.r;
  let bp = null;
  for (const r of roots) {
    const t = (r.it.title || "").replace(/\s+/g, " ").trim();
    const n = commonPrefixLen(prob, t);
    if (n >= 4 && (!bp || n > bp.n)) bp = { r, n };
  }
  if (bp) return bp.r;
  if (item.sev) {
    const bySev = roots.find((r) => r.it.sev === item.sev);
    if (bySev) return bySev;
  }
  return null;
}

// "지금 해야 할 일" 목록 — 최대 3건.
function parseActionItems(docs, segs) {
  if (!docs || !docs.length) return [];
  const li = latestReportIndex(docs);
  const docIdx = li >= 0 ? li : docs.length - 1;
  const doc = docs[docIdx];
  if (!doc) return [];
  const text = doc.text || "";
  const items = [];
  // (1) 권고 절의 [P0]/[P1] 항목
  for (const sec of splitSections(text)) {
    if (!sec.kind || sec.kind.kind !== "fix") continue;
    for (const line of sec.lines) {
      const m = /^\s*(?:[-*+]\s*)?\[(P[0-3])\]\s*(.+)$/.exec(line);
      if (!m) continue;
      const pri = m[1];
      if (pri !== "P0" && pri !== "P1") continue; // P2/P3 는 '지금' 할 일이 아니다
      const rest = m[2];
      const problem = firstClause(rest);
      const action = pickField(rest, ["보완", "조치", "권고"]);
      if (!problem || !action) continue;
      items.push({ pri, problem, action, sev: pickSev(rest), docIdx });
    }
  }
  // (2) 권고 절에 항목이 없으면 루트의 '보완:' 필드로 대체 (심각도 순)
  if (!items.length) {
    const fixes = parseRootFixes(text).filter((r) => r.fix);
    fixes.sort((a, b) => (SEV_ORDER[b.sev] || 0) - (SEV_ORDER[a.sev] || 0));
    for (const r of fixes) {
      items.push({ pri: PRIO_BY_SEV[r.sev] || "P3", problem: r.title, action: r.fix, sev: r.sev, docIdx });
    }
  }
  if (!items.length) return [];
  // 대상 루트 카드(같은 리포트 안의 루트만) 매칭 — 클릭 시 그 카드로 이동.
  const roots = (segs || []).map((it, i) => ({ it, i })).filter((x) => x.it.kind === "root" && x.it.docIdx === docIdx);
  for (const it of items) {
    const r = matchRoot(it, roots);
    it.goto = r ? r.i : null;
  }
  return items.slice(0, 3);
}

// "지금 해야 할 일" 블록 HTML — 없으면 빈 문자열(빈 영역을 만들지 않는다).
function renderTodoList(items) {
  if (!items || !items.length) return "";
  const rows = items.map((it) => {
    const pri = `<span class="badge ${DIAG_BADGES[it.pri] || "bx-p3"}">${esc(it.pri)}</span>`;
    const body = `<span class="rt-problem">${esc(it.problem)}</span><span class="rt-action">${esc(it.action)}</span>`;
    return it.goto != null
      ? `<li><button class="rs-todo-item" data-goto="${it.goto}" title="이 항목의 발견 카드로 이동합니다">${pri}${body}</button></li>`
      : `<li><span class="rs-todo-item plain">${pri}${body}</span></li>`;
  }).join("");
  return `<div class="rs-todo">
    <div class="rs-todo-head">
      <span class="rs-nav-label">지금 해야 할 일</span>
      <span class="rs-todo-note">누르면 그 항목의 발견으로 이동합니다</span>
    </div>
    <ol class="rs-todo-list">${rows}</ol>
  </div>`;
}

function renderReportSummary(s, docs, segs) {
  const top = $("reportSummary");
  if (!top) return;
  const isDiag = s && s.diag;
  if (!isDiag || !docs.length) { top.classList.add("hidden"); top.innerHTML = ""; return; }
  const st = reportStats(statsDocs(docs));
  top.classList.remove("hidden");
  const worst = st.worst && st.worst.title
    ? `<div class="rs-why"><span class="rs-why-lbl">최고 위험</span>${esc(st.worst.title)} <span class="rs-why-tag">${esc(st.worst.sev)}${st.worst.ver === "실증" ? " · 직접 확인" : st.worst.ver === "징후" ? " · 일부 확인" : " · 추측"}</span></div>`
    : "";
  // B1) 지금 해야 할 일 — 권고 절의 P0/P1 항목 (없으면 조용히 숨김)
  const todo = renderTodoList(parseActionItems(docs, segs));
  top.innerHTML = `
    <div class="rs-card">
      <div class="rs-topline">
        <div class="rs-grade ${st.grade.cls}" title="${esc(st.grade.why)}">
          <span class="rs-letter">${st.grade.letter}</span>
          <div class="rs-grade-txt"><b>${esc(st.grade.label)}</b></div>
        </div>
        <div class="rs-head">
          <div class="rs-title"><b>${st.roots}개 발견</b><span class="rs-mini"><i class="c-crit">치명 ${st.sev["치명"]}</i> · <i class="c-high">높음 ${st.sev["높음"]}</i> · <i class="c-med">중간 ${st.sev["중간"]}</i> · <i class="c-low">낮음 ${st.sev["낮음"]}</i></span></div>
          <div class="rs-why-note">${esc(st.grade.why)} · 위험지수 ${st.score.toFixed(1)}/10</div>
        </div>
        <div class="rs-actions">
          <button id="rsCopy" class="rs-btn" title="리포트 전체를 클립보드에 복사">복사</button>
          <button id="rsPdf" class="rs-btn primary" title="리포트를 인쇄 대화상자에서 PDF로 저장">PDF</button>
          <button id="rsExport" class="rs-btn" title="리포트를 Markdown(.md) 파일로 저장">MD</button>
          <button id="rsExportHtml" class="rs-btn" title="리포트를 자체 완성형 HTML 파일로 저장">HTML</button>
          <button id="rsToggle" class="rs-btn rs-toggle" aria-expanded="false" title="필터·바로가기 펼치기/접기">자세히</button>
        </div>
      </div>
      ${worst}
      <!-- H1/B3) 접힘 상태에서도 항상 보이는 정보 — 등급·위험지수·근거·발견 분포 위에
           '믿어야 할 정도' 와 '지금 해야 할 일' 을 둔다. 서랍에는 필터·점프·범례만 둔다. -->
      <div class="rs-always">
        <div class="rs-trust-row" title="직접 열어 확인한 정도 — 직접 확인(초록) · 일부 확인(노랑) · 추측(회색)">
          <span class="rs-nav-label">이 리포트를 얼마나 믿어야 하나</span>
          <span class="rs-vchip v-proof" title="직접 요청해 확인한 취약점"><b>${st.ver["실증"]}</b> 직접 확인</span>
          <span class="rs-vchip v-sig" title="일부 정황만 확인됨"><b>${st.ver["징후"]}</b> 일부 확인</span>
          <span class="rs-vchip v-assume" title="코드·설명 기반 추론(미확인)"><b>${st.ver["가정"]}</b> 추측</span>
        </div>
        ${todo}
      </div>
      <span id="rsExportStatus" class="rs-export-status"></span>
      <div class="rs-drawer">
        ${renderDiagNav(st, segs)}
        <div class="rs-legend">
          <span class="rs-legend-item"><span class="badge bx-crit">치명</span>위험도(치명→낮음)</span>
          <span class="rs-legend-item"><span class="badge bx-proof">실증</span>직접 확인함</span>
          <span class="rs-legend-item"><span class="badge bx-sig">징후</span>일부 확인</span>
          <span class="rs-legend-item"><span class="badge bx-assume">가정</span>추측(미확인)</span>
          <span class="rs-legend-item rs-legend-prio">P0 지금 바로 · P1 이번 주 · P2 한 달 · P3 참고</span>
        </div>
      </div>
    </div>`;
  const exp = $("rsExport");
  const cpy = $("rsCopy");
  const expH = $("rsExportHtml");
  const pdf = $("rsPdf");
  const tgl = $("rsToggle");
  if (exp) exp.onclick = async () => await exportReport(s);
  if (expH) expH.onclick = async () => await exportReport(s, true);
  if (cpy) cpy.onclick = async () => await copyReport(s);
  if (pdf) pdf.onclick = () => printReport(s);
  if (tgl) tgl.onclick = () => toggleSummary();
  // 위험도 필터(루트 보기) — 같은 칩을 다시 누르면 해제.
  document.querySelectorAll("#reportSummary [data-f]").forEach((chip) => {
    chip.onclick = () => {
      const v = chip.dataset.f;
      diagFilter = v === "ALL" ? null : (diagFilter && diagFilter.has(v) && diagFilter.size === 1 ? null : new Set(v === "ALL" ? [] : [v]));
      renderResults();
    };
  });
  // 바로가기 — 해당 카드로 스크롤.
  document.querySelectorAll("#reportSummary [data-goto]").forEach((chip) => {
    chip.onclick = () => gotoCardSeg(Number(chip.dataset.goto));
  });
  // 리포트 영역이 이보다 낮으면 접고 시작해 본문을 우선 보여준다.
  const rvH = ($("view-results") || {}).clientHeight || 0;
  summaryTightWindow = rvH > 0 && rvH < SUMMARY_TIGHT_H;
  syncSummaryCollapse();
}

// 진단 결과 위험도 필터 내비(루트 카드처럼 카드 렌더/숨김)
// 위험도 필터 내비 — 위험도별로 루트 카드만 골라 본다(같은 칩을 다시 누르면 해제).
function renderDiagNav(st, segs) {
  const sevs = ["치명", "높음", "중간", "낮음"];
  const clsFor = { "치명": "crit", "높음": "high", "중간": "med", "낮음": "low" };
  const active = diagFilter;
  const chip = (lbl, v, cls, n) => {
    const on = v === "ALL" ? !active || !active.size : !!(active && active.has(v));
    const cnt = (n != null && v !== "ALL") ? ` <b>${n}</b>` : "";
    return `<button class="rs-nav-chip ${cls}${on ? " on" : ""}" data-f="${v}" title="${lbl} 위험만 보기">${lbl}${cnt}</button>`;
  };
  const filteredCount = (segs || []).filter((it) => it.kind === "root").length;
  const filtered = !!(active && active.size);
  const rootCountTxt = filtered
    ? `${filteredCount}개 표시 · 전체 ${st.roots}개`
    : `위험 ${st.roots}개`;
  return `<div class="rs-nav"><span class="rs-nav-label">위험도</span>
     ${chip("전체", "ALL", "n-all")}
     ${sevs.map((sv) => chip(sv, sv, "n-" + clsFor[sv], st.sev[sv])).join("")}
     ${filtered ? `<span class="rs-nav-note">필터 적용 중 — 같은 칩을 누르면 전체로 돌아옵니다</span>` : ""}
     <span class="rs-nav-sep"></span>
     ${renderJumpNav(segs)}
     <span class="rs-nav-count">${rootCountTxt}</span></div>`;
}

// 바로가기 내비 — 카드가 많아도 원하는 섹션으로 한 번에 이동(요약·해야 할 일·루트 N·실측…).
const JUMP_CLS = { "치명": "j-crit", "높음": "j-high", "중간": "j-med", "낮음": "j-low" };
// G1) 칩 라벨을 종류별로 구분한다 — "위험 N" 뿐이면 무엇인지 모른다.
const JUMP_LABEL = {
  report: "리포트",
  prelude: "요약",
  fix: "해야 할 일",
  proof: "직접 확인",
  control: "잘 되고 있는",
  limit: "한계",
  appendix: "부록",
  tail: "그 밖의 내용",
};
function renderJumpNav(segs) {
  if (!segs || segs.length < 3) return "";
  let rootNo = 0;
  let lastDoc = null;
  const chips = segs
    .map((it, i) => {
      const cls = it.sev ? (JUMP_CLS[it.sev] || "") : `j-${it.kind || "none"}`;
      // 루트 라벨은 "위험 N" — 리포트(1차/최종)마다 다시 1부터 센다.
      if (it.docIdx != null && it.docIdx !== lastDoc) { lastDoc = it.docIdx; rootNo = 0; }
      const lb = it.kind === "root" ? `위험 ${++rootNo}` : (JUMP_LABEL[it.kind] || "결과");
      const tip = it.kind === "root" ? (it.title || lb) : (it.sec || it.title || lb);
      return `<button class="rs-jump-chip ${cls}" data-goto="${i}" title="${esc(tip)}"><span class="jc-label">${esc(lb)}</span></button>`;
    })
    .join("");
  return `<div class="rs-jump"><span class="rs-nav-label">바로가기</span>${chips}</div>`;
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
.table-scroll{overflow-x:auto}
.md-body table{min-width:520px}
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
.bx-p0{background:rgba(240,68,82,.2);color:#ff8d9a}
.bx-p1{background:rgba(255,138,61,.2);color:#ffb183}
.bx-p2{background:rgba(255,194,14,.2);color:#ffd25e}
.bx-p3{background:rgba(160,168,182,.18);color:#aab4c2}
abbr[title]{text-decoration:underline dotted;cursor:help}
.df-sep{margin:0 3px;color:#8a94a3}
.cvss-num{font-family:'JetBrains Mono',Consolas,monospace;font-size:14px;color:#ff8f8f}
.cvss-den{margin:0 4px 0 1px;color:#8a94a3;font-size:12px}
.cvss-vec{font-family:'JetBrains Mono',Consolas,monospace;font-size:11px!important;color:#9aa5b3!important;background:rgba(255,255,255,.04)!important}
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
@media print{:root{color-scheme:light}body{background:#fff!important;color:#111!important}.wrap{max-width:100%!important;padding:0!important}.cover{background:#fff!important;border-color:#ddd!important;border-radius:0!important;padding:14px 0!important;border-bottom:1px solid #e2e5ea}.cover h1{color:#111!important}.brand{color:#4a4886!important}.meta{color:#555!important}.md-body h1,.md-body h2,.md-body h3,.md-body h4,.md-body h5,.md-body h6{color:#111!important}.md-body h1,.md-body h2{border-bottom-color:#e2e5ea!important}.md-body pre{background:#f7f8fa!important;border-color:#e2e5ea!important;white-space:pre-wrap}.md-body pre code{color:#222!important}.md-body table{font-size:12px}.md-body th,.md-body td{border-color:#e2e5ea!important}.md-body th{background:#f2f3f6!important}.md-body blockquote{border-left-color:#cfd4db!important;color:#444!important;background:transparent!important}.md-body code{background:rgba(200,60,70,.08)!important;color:#a62!important}.badge,.dchip{border:1px solid #ccc!important;background:#f5f6f8!important;color:#333!important}.diag-flow,.diag-field,.sim{background:#fff!important;border-color:#e2e5ea!important}.sim-head{background:#f7f8fa!important;border-bottom-color:#e2e5ea!important}.diag-step{background:#f7f8fa!important;border-color:#dbe0e6!important;color:#222!important}.diag-step.vuln{border-color:#d96!important;color:#a62!important;background:#fdf3ee!important}.diag-step.loss{border-color:#d9b84c!important;color:#8a6d00!important;background:#fdf9ec!important}.diag-field.field-risk .df-label{color:#a62!important}.diag-field.field-fix{background:#f2faf5!important;border-color:#b6dcc4!important}.diag-field.field-loss{background:#fdf9ec!important;border-color:#e2cf8a!important}.diag-field.field-fix .df-label{color:#1d7a45!important}.diag-field.field-loss .df-label{color:#8a6d00!important}.diag-arrow{color:#666!important}.sim-bubble{page-break-inside:avoid}.sim-n{background:#eef0f3!important;border-color:#d5dae0!important;color:#555!important}.sim-ctr,.sim-ctl,.sim-track,.sim-prog,.sim-note,.sim-play{display:none!important}.sim-steps{display:block!important}.sim-step{page-break-inside:avoid;margin-bottom:8px}.sim-tag{color:#333!important}.verify-chip,.badge,.dchip{print-color-adjust:exact;-webkit-print-color-adjust:exact}}.md-body h1,.md-body h2,.md-body h3,.md-body h4{page-break-after:avoid}
`;

// ── 리포트 PDF/인쇄: 숨김 iframe에 리포트를 렌더링하고 인쇄 대화상자(⇒ PDF 저장) 호출 ──
function printHtml(html, st) {
  let fr = document.getElementById("rsPrintFrame");
  if (!fr) {
    fr = document.createElement("iframe");
    fr.id = "rsPrintFrame";
    fr.style.cssText = "position:fixed;right:0;bottom:0;width:0;height:0;border:0;visibility:hidden";
    document.body.appendChild(fr);
  }
  const doPrint = () => { try { fr.contentWindow.focus(); fr.contentWindow.print(); } catch (e) { /* 인쇄 불가 시 조용히 무시 */ } };
  fr.onload = doPrint;
  const d = fr.contentDocument;
  d.open();
  d.write(html);
  d.close();
  if (d.readyState !== "loading") setTimeout(doPrint, 80);
  if (st) { st.textContent = "인쇄 대화상자에서 'PDF로 저장'을 선택하세요"; st.className = "rs-export-status ok"; }
}
function printReport(s) {
  const name = reportBaseName(s);
  printHtml(diagToExportHtml(s, name), $("rsExportStatus"));
}

function exportHtmlShell(title, meta) {
  const date = new Date().toLocaleString("ko-KR");
  return `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title><style>${EXPORT_CSS}</style></head>
<body><div class="wrap">
 <div class="cover">
   <div class="brand">🛡 RedCell · 보안 리포트</div>
   <h1>${title}</h1>
   <div class="meta">${meta} · 생성 ${date}</div>
 </div>
 <div class="md-body">__RC_BODY__</div>
</div></body></html>`;
}
function diagToExportHtml(s, name) {
  resetTermTips(); // 내보내기 본문도 문서당 첫 등장만 툴팁
  const body = mdToHtml(reportMarkdown(s));
  const target = s && s.host ? escHtml(s.host + (s.port ? ":" + s.port : "")) : "(—)";
  const title = escHtml((name || "RedCell 진단 리포트").trim() || "RedCell 진단 리포트");
  return exportHtmlShell(title, `대상 ${target}${reportMetaLine(s)}`).replace("__RC_BODY__", body);
}
function segmentToExportHtml(name, target, text) {
  resetTermTips(); // 절 하나 = 문서 하나
  const body = mdToHtml(text);
  const title = escHtml((name || "RedCell 결과").trim() || "RedCell 결과");
  return exportHtmlShell(title, `대상 ${target || "(—)"}`).replace("__RC_BODY__", body);
}

// 리포트 표지(메타) — 내보낸 파일·복사본이 스스로를 설명한다.
// (대상 · 점검일 · 등급 · 위험지수 · 발견 분포 · 검증 상태 분포)
function reportMetaLine(s) {
  const st = reportStats(statsDocs(resultDocs(s)));
  if (!st.roots) return "";
  return ` · 등급 ${st.grade.letter}(${st.grade.label}) · 위험지수 ${st.score.toFixed(1)}/10 · 발견 ${st.roots}건`
    + ` (치명 ${st.sev["치명"]}·높음 ${st.sev["높음"]}·중간 ${st.sev["중간"]}·낮음 ${st.sev["낮음"]})`
    + ` · 직접확인 ${st.ver["실증"]}·추측 ${st.ver["가정"]}`;
}

// 리포트 표지 블록(마크다운) — MD 저장·클립보드 복사·인쇄용.
function reportCover(s, docs) {
  const st = reportStats(docs);
  const target = (s && s.host) ? (s.host + (s.port ? ":" + s.port : "")) : "(대상 미상)";
  const now = new Date();
  const p2 = (n) => String(n).padStart(2, "0");
  const stamp = `${now.getFullYear()}-${p2(now.getMonth() + 1)}-${p2(now.getDate())} ${p2(now.getHours())}:${p2(now.getMinutes())}`;
  const sev = st.sev;
  const lines = [
    `> **RedCell 보안 진단 리포트**`,
    `> 대상 ${target} · 점검일 ${stamp}`,
  ];
  if (st.roots) {
    lines.push(`> 등급 ${st.grade.letter} (${st.grade.label}) · 위험지수 ${st.score.toFixed(1)}/10 · 발견 ${st.roots}건`
      + ` (치명 ${sev["치명"]} · 높음 ${sev["높음"]} · 중간 ${sev["중간"]} · 낮음 ${sev["낮음"]})`);
    lines.push(`> 검증 상태 — 직접 확인 ${st.ver["실증"]} · 일부 확인 ${st.ver["징후"]} · 추측 ${st.ver["가정"]}`
      + (st.worst && st.worst.title ? ` · 최고 위험: ${st.worst.title}` : ""));
  } else {
    lines.push(`> 등급 ${st.grade.letter} (${st.grade.label}) — 점검 범위 안에서 알려진 결함을 확인하지 못했습니다`);
  }
  return lines.join("\n");
}

function reportMarkdown(s) {
  // 내보내기·복사·인쇄는 최신 발행 리포트(전 차수 취합본) 1건만 — 로그 나열이 아니다.
  const docs = statsDocs(resultDocs(s));
  const body = docs.map((d) => d.text).join("\n\n");
  const cover = reportCover(s, docs);
  return cover ? `${cover}\n\n${body}` : body;
}
function reportBaseName(s) {
  return ((s && (s.name || "redcell-report")) || "redcell-report").replace(/[^\w가-힣 -]/g, "").trim() || "redcell-report";
}
async function writeReport(name, content, format, st) {
  try {
    const path = await invoke("write_report", { name, content, format });
    st.textContent = "💾 " + path;
    st.className = "rs-export-status ok";
  } catch (e) {
    st.textContent = "저장 실패: " + e;
    st.className = "rs-export-status err";
  }
}
async function copyText(md, st) {
  const done = () => { if (st) { st.textContent = "복사됨"; st.className = "rs-export-status ok"; } };
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(md);
      done();
    } else {
      const ta = document.createElement("textarea");
      ta.value = md; document.body.appendChild(ta); ta.select();
      document.execCommand("copy"); document.body.removeChild(ta);
      done();
    }
  } catch (e) {
    if (st) { st.textContent = "복사 실패"; st.className = "rs-export-status err"; }
  }
}

async function exportReport(s, asHtml) {
  const btn = $("rsExport");
  const btnH = $("rsExportHtml");
  const st = $("rsExportStatus");
  const target = asHtml ? btnH : btn;
  if (!target || !st) return;
  const name = reportBaseName(s);
  target.disabled = true; st.textContent = "저장 중…";
  const content = asHtml ? diagToExportHtml(s, name) : reportMarkdown(s);
  await writeReport(name, content, asHtml ? "html" : "md", st);
  target.disabled = false;
}
async function copyReport(s) {
  await copyText(reportMarkdown(s), $("rsExportStatus"));
}

// 결과 카드별 개별 내보내기 (여러 결과가 있을 때 각각 내보낼 수 있게 한다)
function segmentExportBar(i) {
  return `<footer class="md-export">
    <span class="rd-exp-status"></span>
    <div class="md-export-btns">
      <button class="rd-exp" data-ix="${i}" data-act="copy" title="이 결과 원문을 클립보드에 복사">복사</button>
      <button class="rd-exp" data-ix="${i}" data-act="pdf" title="이 결과를 인쇄 대화상자에서 PDF로 저장">PDF</button>
      <button class="rd-exp" data-ix="${i}" data-act="md" title="이 결과를 .md 파일로 저장">MD</button>
      <button class="rd-exp" data-ix="${i}" data-act="html" title="이 결과를 자체 완성형 HTML 파일로 저장">HTML</button>
    </div>
  </footer>`;
}
function segTarget() {
  const s = cur();
  return (s && (s.host || "") + (s.port ? ":" + s.port : "")) || "";
}
async function exportSegment(ix, asHtml, btn) {
  const seg = resultsSegs[ix];
  if (!seg) return;
  const card = btn.closest(".md-card");
  const st = card ? card.querySelector(".rd-exp-status") : null;
  if (!st) return;
  const s = cur();
  const name = (reportBaseName(s) + "-" + (seg.title || (seg.kind || "result"))).replace(/[^\w가-힣-]/g, "-").trim() || "redcell-result";
  btn.disabled = true; st.textContent = "저장 중…";
  const content = asHtml ? segmentToExportHtml(name, segTarget(), seg.text) : seg.text;
  await writeReport(name, content, asHtml ? "html" : "md", st);
  btn.disabled = false;
}
async function copySegment(ix, btn) {
  const seg = resultsSegs[ix];
  if (!seg) return;
  const card = btn.closest(".md-card");
  await copyText(seg.text, card ? card.querySelector(".rd-exp-status") : null);
}
function printSegment(ix, btn) {
  const seg = resultsSegs[ix];
  if (!seg) return;
  const card = btn.closest(".md-card");
  const st = card ? card.querySelector(".rd-exp-status") : null;
  const s = cur();
  const name = (reportBaseName(s) + "-" + (seg.title || (seg.kind || "result"))).replace(/[^\w가-힣-]/g, "-").trim() || "redcell-result";
  printHtml(segmentToExportHtml(name, segTarget(), seg.text), st);
}

// ── 진단 리포트를 루트 카드로 분할 (prelude/루트/권고·실측·통제·한계·부록) ──
const RISK_CLS = { "치명": "rk-crit", "높음": "rk-high", "중간": "rk-med", "낮음": "rk-low" };

// A1) "## " 절 경계마다 카드를 만든다.
//     절 제목 정규화 — 번호·공백·괄호·앞뒤 표현 차이를 허용하고 핵심 키워드로 판별한다.
//     (예: "## 5. 개선·보완 권고 (우선순위)" 와 "## 5. 개선·보완 권고" · "## 한계와 미검증 영역" 이
//      같은 종류로 잡히게 — 소문자·공백 제거 후 핵심 키워드로 본다.)
//     매칭이 안 되는 절은 아래 tail(fallback) 로 모은다(안전).
const SEC_KINDS = [
  { kind: "fix", title: "해야 할 일 (우선순위별)", re: /(권고|개선|보완)/ },
  { kind: "proof", title: "직접 확인한 것", re: /(실측|확인한)/ },
  { kind: "control", title: "이미 잘 되고 있는 부분", re: /(통제|잘되고)/ },
  { kind: "limit", title: "확인하지 못한 부분 (한계)", re: /(한계|미검증)/ },
  { kind: "appendix", title: "부록", re: /부록/ },
];
// 카드 최종 순서 — 실측·통제·한계·부록은 루트 뒤로, '기타(tail)' 는 맨 뒤.
const SEC_ORDER = ["proof", "control", "limit", "appendix", "tail"];

// 절 제목 → 카드 종류 (없으면 null → 기존 tail 동작으로 fallback).
function sectionKind(title) {
  const norm = String(title || "").toLowerCase().replace(/\s+/g, "");
  for (const k of SEC_KINDS) if (k.re.test(norm)) return k;
  return null;
}

function reportLabel(d) {
  const h1 = (d.text || "").match(/^#\s+(.*)$/m);
  if (h1) return h1[1].trim().slice(0, 60);
  return d.report === "early" ? "1차 리포트" : d.report === "final" ? "최종 리포트" : "결과";
}

function segmentDiag(docs) {
  const out = [];
  docs.forEach((d, di) => {
    // 리포트가 2건 이상(1차+최종)이면 첫 리포트에도 구분 배너를 단다 —
    // 없으면 1차 리포트가 어떤 문서인지 카드 목록에서 알 수 없다.
    if (docs.length > 1) {
      out.push({ kind: "report", title: reportLabel(d), sev: null, text: "", seq: d.seq, ts: d.ts, docIdx: di });
    }
    out.push(...segmentDocDiag(d, di));
  });
  return out.filter((it) => it.text.trim() || it.kind === "report");
}

// 리포트 1건 → 카드 목록.
// 루트 앞(요약·범위)은 prelude, 루트는 루트 카드, 루트 뒤 "## " 절은 종류별로 카드.
function segmentDocDiag(d, di) {
  const out = [];
  const pre = [];    // 루트 앞(요약·범위)
  const roots = [];  // 발견(루트) 카드
  const named = [];  // 절 카드(권고·실측·통제·한계·부록·기타)
  let cur = null;    // 현재 루트 누적
  let rootNo = 0;
  let sec = null;    // 현재 이름 있는 절
  let tail = null;   // 종류를 못 알아본 절(기존 tail 동작으로 fallback)
  let seenRoot = false;

  const flushRoot = () => {
    if (cur) {
      roots.push({ kind: "root", title: cur.title, sev: cur.sev, text: cur.buf.join("\n"), docIdx: di, rootNo: cur.rootNo });
      cur = null;
    }
  };
  const flushSec = () => {
    if (sec) { named.push({ kind: sec.kind, title: sec.title, sec: sec.sec, text: sec.buf.join("\n"), docIdx: di }); sec = null; }
  };
  const flushTail = () => {
    if (tail && tail.buf.length) { named.push({ kind: "tail", title: tail.title, sec: tail.sec, text: tail.buf.join("\n"), docIdx: di }); }
    tail = null;
  };

  for (const raw of (d.text || "").split(/\r?\n/)) {
    const line = raw.trim();
    // 1) 루트 헤딩 → 새 루트 카드 시작
    if (ROOT_HEADING_RE.test(line)) {
      flushRoot(); flushSec(); flushTail();
      seenRoot = true;
      rootNo++;
      const txt = line.replace(/^#{1,4}\s*루트\s*\d*\.?\s*/, "").trim();
      const sevM = txt.match(/\[(치명|높음|중간|낮음)\]/);
      cur = {
        title: txt.replace(/\s*\[(치명|높음|중간|낮음)\]\s*/, "").trim(), // A4) 카드 제목 = 실제 루트 제목
        sev: sevM ? sevM[1] : null,
        buf: [raw],
        rootNo,
      };
      continue;
    }
    // 2) "## " 절 경계 — 루트가 나온 뒤에만 절을 나눈다(앞부분은 prelude 로 남긴다)
    if (seenRoot && /^##\s+/.test(line)) {
      flushRoot(); flushSec();
      const secTitle = line.replace(/^#{1,6}\s*/, "").trim();
      const k = sectionKind(secTitle);
      if (k) {
        flushTail();
        sec = { kind: k.kind, title: k.title, sec: secTitle, buf: [raw] };
      } else if (!tail) {
        tail = { kind: "tail", title: "그 밖의 내용", sec: secTitle, buf: [raw] };
      } else {
        tail.buf.push(raw); // 못 알아본 절은 기존 tail 처럼 한 장에 모은다
      }
      continue;
    }
    // 3) 내용 누적
    if (cur) cur.buf.push(raw);
    else if (sec) sec.buf.push(raw);
    else if (tail) tail.buf.push(raw);
    else pre.push(raw);
  }
  flushRoot(); flushSec(); flushTail();
  if (pre.length) out.push({ kind: "prelude", title: "요약 · 점검 범위", sev: null, text: pre.join("\n"), docIdx: di });
  // A3) 순서 — 요약(prelude) → 해야 할 일(fix) → 발견(루트) → 실측·통제·한계·부록.
  //     왜 이 순서인가: 이 앱의 사용자는 보안 전문가가 아니다.
  //     "지금 뭘 해야 하지?" 가 루트 디테일(증거·재현·영향)보다 먼저 보여야 한다 —
  //     그래서 권고 카드는 요약 바로 다음(루트보다 앞)으로 올린다.
  const fixes = named.filter((n) => n.kind === "fix");
  const rest = SEC_ORDER.map((k) => named.filter((n) => n.kind === k)).flat();
  out.push(...fixes, ...roots, ...rest);
  return out;
}

function renderResults() {
  const s = cur();
  const el = $("resultsBody");
  const cnt = $("resultsCount");
  const docs = s ? resultDocs(s) : [];
  if (cnt) { cnt.textContent = String(docs.length); cnt.style.display = docs.length ? "inline-flex" : "none"; }
  if (!el) return;
  // 재렌더 전 이전 플레이어의 재생 타이머 정리
  el.querySelectorAll("[data-sim]").forEach(simStop);
  if (!docs.length) {
    renderReportSummary(s, docs, null); // 결과 없음 → 요약도 감춘다
    el.innerHTML = `<div class="placeholder">아직 결과가 없습니다.<br/>진단이 끝나면 여기에 리포트가 표시됩니다.</div>`;
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
  resultsSegs = segs;
  renderReportSummary(s, docs, segs);
  // B2) 툴팁은 '문서(=발행 리포트)당 첫 등장'만 — 1차 리포트와 최종 리포트는 각각 따로 센다.
  let tipDoc = null;
  el.innerHTML = segs.map((it, i) => {
    if (it.docIdx != null && it.docIdx !== tipDoc) { tipDoc = it.docIdx; resetTermTips(); }
    const isRoot = it.kind === "root";
    const rk = it.sev ? RISK_CLS[it.sev] || "" : "";
    // A2) 카드 종류별 배지 — '막는 방법' 처럼 내용과 다른 라벨은 쓰지 않는다.
    const tag = isRoot ? `<span class="md-kind root">발견</span>`
      : it.kind === "report" ? `<span class="md-kind doc">리포트</span>`
      : it.kind === "prelude" ? `<span class="md-kind pre">요약·범위</span>`
      : it.kind === "fix" ? `<span class="md-kind fix">해야 할 일</span>`
      : it.kind === "proof" ? `<span class="md-kind proof">직접 확인</span>`
      : it.kind === "control" ? `<span class="md-kind control">잘 되고 있는</span>`
      : it.kind === "limit" ? `<span class="md-kind limit">한계</span>`
      : it.kind === "appendix" ? `<span class="md-kind appendix">부록</span>`
      : it.kind === "tail" ? `<span class="md-kind tail">기타</span>`
      : `<span class="md-kind doc">결과</span>`;
    // 루트 카드는 실제 루트 제목, 절 카드는 원래 절 제목(번호 포함)을 보여준다.
    const title = isRoot || it.kind === "report" ? esc(it.title || "")
      : (it.kind === "prelude" || it.kind === "doc") ? (it.seq != null ? `#${it.seq}` : "")
      : esc(it.sec || it.title || "");
    return `<article class="md-card ${rk}${isRoot ? " is-root" : ""}" data-ix="${i}">
       <header class="md-card-head">
         ${tag}<span class="md-card-title">${title}</span>
         <span class="md-card-ts">${hhmm(it.ts)}</span>
       </header>
       <div class="md-body">${mdToHtml(it.text)}</div>
       ${it.kind === "report" ? "" : segmentExportBar(i)}
     </article>`;
  }).join("");
  if (s && s.diag && s.status === "done") el.insertAdjacentHTML("beforeend", renderNextActions(s));
  wireSimPlayers(el);
}

function escHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/* 미니 마크다운 → HTML (의존성 없음). 입력은 먼저 이스케이프한 뒤 변환하므로 안전. */
// F1) 우선순위 배지를 4단계로 나눈다 — 전부 같은 색이면 우선순위가 구분되지 않는다.
const DIAG_BADGES = { "치명": "bx-crit", "높음": "bx-high", "중간": "bx-med", "낮음": "bx-low", "정보": "bx-info", "가정": "bx-assume", "실증": "bx-proof", "징후": "bx-sig", "P0": "bx-p0", "P1": "bx-p1", "P2": "bx-p2", "P3": "bx-p3" };

// ── B) 비전문가용 전문어 툴팁 사전 ────────────────────────────────────────────
// 이 앱의 사용자는 "보안을 잘 모르는 사람"이다. 리포트 본문에 나오는 전문어를
// 첫 등장에서만 <abbr title="..."> 로 감싸 한 줄 설명을 건다.
// (반복 감싸면 화면이 시끄러워지므로 문서당 첫 등장만 감싼다 — B2)
// CVSS · CWE · OWASP 의 필드용 툴팁은 lane4(classifyHtml) 가 따로 담당한다 —
// 여기서는 본문에서 자유롭게 등장하는 용어만 맡는다(중복 감싸기 금지).
const TERM_TIPS = [
  { key: "cwe", re: /\bCWE-(\d{1,4})\b/, tip: (m) => `소프트웨어 취약점 분류 번호(${m[1]}번 항목)` },
  { key: "owasp", re: /\bOWASP\s+A(\d{2})(?::(\d{4}))?/, tip: (m) => `OWASP이 매년 공개하는 가장 위험한 웹 취약점 10종 중 ${Number(m[1])}번${m[2] ? `(${m[2]}년 목록)` : ""}` },
  { key: "idor", re: /\bIDOR\b/, tip: "남의 다른 번호 주소로 들어가 정보를 보는 약점" },
  { key: "sqli", re: /\bSQL\s*주입(?![가-힣])|\bSQL\s*Injection\b|\bSQLi\b/i, tip: "입력값을 데이터베이스 명령에 섞어 정보를 빼가는 방법" },
  { key: "xss", re: /\bXSS\b/, tip: "웹 페이지에 스크립트를 심어 다른 사용자 화면에서 실행하는 방법" },
  { key: "csrf", re: /\bCSRF\b/, tip: "사용자 대신 요청을 보내게 만드는 방법" },
  { key: "ssrf", re: /\bSSRF\b/, tip: "서버가 대신 다른 주소에 요청하게 만드는 방법" },
  { key: "cookie-httponly", re: /\bHttpOnly\b/, tip: "브라우저에 로그인 정보를 안전하게 남기는 설정" },
  { key: "cookie-secure", re: /\bSecure\b(?=[^\n]{0,40}(?:HttpOnly|SameSite|Set-Cookie|쿠키|Cookie|cookie))/, tip: "브라우저에 로그인 정보를 안전하게 남기는 설정" },
  { key: "cookie-samesite", re: /\bSameSite\b/, tip: "브라우저에 로그인 정보를 안전하게 남기는 설정" },
  { key: "redirect", re: /리다이렉트/, tip: "사용자를 다른 사이트로 넘기는 동작" },
  { key: "waf", re: /\bWAF\b/, tip: "공격을 막는 방화벽" },
  { key: "jwt", re: /\bJWT\b/, tip: "로그인 상태를 담은 서명된 값" },
  { key: "cors", re: /\bCORS\b/, tip: "다른 사이트가 내 API를 호출해도 되게 열어주는 설정" },
  { key: "sso", re: /\bSAML\b|\bOIDC\b/, tip: "다른 서비스의 계정으로 로그인하게 해주는 방식" },
  { key: "csp", re: /\bCSP\b/, tip: "스크립트 실행 규칙을 지정하는 헤더" },
  { key: "hsts", re: /\bHSTS\b/, tip: "브라우저가 항상 암호화 연결만 쓰게 강제하는 설정" },
  { key: "race", re: /\brace\s+condition\b/i, tip: "동시에 들어온 요청의 처리 순서가 잘못 엇갈려 생기는 결함" },
  { key: "race", re: /레이스\s*컨디션/, tip: "동시에 들어온 요청의 처리 순서가 잘못 엇갈려 생기는 결함" },
  { key: "session-fixation", re: /세션\s*고정/, tip: "로그인 전에 받은 세션 토큰을 로그인 후에도 그대로 쓰는 결함" },
  { key: "privesc", re: /권한\s*상승/, tip: "일반 사용자 권한으로 관리자 기능에 접근하는 결함" },
  { key: "path-traversal", re: /경로\s*순회|path\s+traversal/i, tip: "경로에 ../ 등을 넣어 의도한 바깥 파일을 읽는 방법" },
  { key: "xxe", re: /\bXXE\b/, tip: "XML 안의 외부 참조를 통해 서버 파일을 읽는 방법" },
  { key: "deserialization", re: /역직렬화/, tip: "신뢰한 데이터를 실행 가능한 형태로 되살리는 과정에서 생기는 결함" },
];
// 이미 툴팁을 건 문서 안에서 다시 감싸지 않기 위한 상태 — 문서(리포트 한 편) 단위로 초기화.
let tipSeen = new Set();
function resetTermTips() { tipSeen = new Set(); }
// 전문어 첫 등장만 <abbr title="설명"> 으로 감싼다.
function tipTerms(s) {
  // 백틱(코드) 안쪽은 건드리지 않는다 — 코드 식별자는 그대로 둔다.
  const parts = s.split(/(`[^`]+`)/g);
  for (let i = 0; i < parts.length; i += 2) {
    let p = parts[i];
    for (const t of TERM_TIPS) {
      if (tipSeen.has(t.key)) continue;
      const re = new RegExp(t.re.source, t.re.flags.indexOf("g") >= 0 ? t.re.flags : t.re.flags + "g");
      const m = re.exec(p);
      if (!m) continue;
      tipSeen.add(t.key);
      const tip = typeof t.tip === "function" ? t.tip(m) : t.tip;
      p = p.slice(0, m.index) + `<abbr title="${esc(tip)}">${m[0]}</abbr>` + p.slice(m.index + m[0].length);
    }
    parts[i] = p;
  }
  return parts.join("");
}
function inlineMd(s) {
  // B) 전문어 툴팁 — 이스케이프된 평문 단계에서 먼저 감싼다(태그·속성 안을 건드리지 않으려고).
  s = tipTerms(s);
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
  ["실증", "bx-proof", "직접 확인함"],
  ["징후", "bx-sig", "일부만 확인"],
  ["가정", "bx-assume", "추측 (직접 확인 못 함)"],
];
// ── E) 약점 번호 툴팁 사전 ────────────────────────────────────────────────
// 비전문가는 "CWE-89" 가 무엇인지 모른다 — 번호마다 한국어 한 줄 설명을 붙인다.
const CWE_TIPS = {
  "22": "경로 조작으로 서버의 임의 파일을 읽는 약점",
  "78": "입력값이 명령으로 실행되어 서버 명령이 돌아가는 약점",
  "79": "웹 페이지에 넣은 스크립트가 그대로 실행되는 약점",
  "89": "입력값을 검증하지 않아 데이터베이스 명령이 실행되는 약점",
  "200": "권한 없는 사용자가 제한된 정보를 볼 수 있는 약점",
  "352": "사용자 요청만으로 다른 사람의 권한이 바뀌는 약점",
  "434": "업로드한 파일이 실행 가능한 코드로 저장되는 약점",
  "502": "신뢰할 수 없는 데이터를 역직렬화해 코드가 실행되는 약점",
  "601": "사용자가 넘긴 주소로 서버가 요청을 보내는 약점",
  "614": "쿠키에 HttpOnly 가 없어 스크립트로 읽힐 수 있는 약점",
  "639": "리소스 소유권을 검사하지 않아 남의 정보를 볼 수 있는 약점",
  "798": "비밀번호·키 같은 자격증명이 코드에 박혀 있는 약점",
  "918": "서버가 지정된 주소로 요청을 보내 정보가 샐 수 있는 약점",
};
const OWASP_TIPS = {
  "A01": "OWASP 가장 위험한 웹 취약점 10종 중 1번 — 접근통제 위반(남의 정보 열람)",
  "A02": "OWASP 가장 위험한 웹 취약점 10종 중 2번 — 암호화 실패(평문 전송·약한 암호)",
  "A03": "OWASP 가장 위험한 웹 취약점 10종 중 3번 — 주입(입력값이 명령으로 실행됨)",
  "A04": "OWASP 가장 위험한 웹 취약점 10종 중 4번 — 안전하지 않은 설계",
  "A05": "OWASP 가장 위험한 웹 취약점 10종 중 5번 — 보안 설정 오류",
  "A06": "OWASP 가장 위험한 웹 취약점 10종 중 6번 — 오래된 라이브러리 사용",
  "A07": "OWASP 가장 위험한 웹 취약점 10종 중 7번 — 인증·인가 실패",
  "A08": "OWASP 가장 위험한 웹 취약점 10종 중 8번 — 소프트웨어·데이터 무결성 실패",
  "A09": "OWASP 가장 위험한 웹 취약점 10종 중 9번 — 기록·모니터링 부족",
  "A10": "OWASP 가장 위험한 웹 취약점 10종 중 10번 — 서버 요청 위조(SSRF)",
};
// CVSS 3.1 벡터 구성요소 → 한국어 (툴팁용).
const CVSS_PART_KO = {
  "AV:N": "네트워크로 접근", "AV:A": "인접 네트워크 접근", "AV:L": "로컬에서 접근", "AV:P": "물리적으로 접근",
  "AC:L": "공격 복잡도 낮음", "AC:H": "공격 복잡도 높음",
  "PR:N": "인증 불필요", "PR:L": "낮은 권한 필요", "PR:H": "높은 권한 필요",
  "UI:N": "사용자 상호작용 없음", "UI:R": "사용자 상호작용 필요",
  "S:U": "영향 범위 그대로", "S:C": "영향 범위 넘어섬",
  "C:N": "기밀성 영향 없음", "C:L": "기밀성 영향 낮음", "C:H": "기밀성 영향 높음",
  "I:N": "무결성 영향 없음", "I:L": "무결성 영향 낮음", "I:H": "무결성 영향 높음",
  "A:N": "가용성 영향 없음", "A:L": "가용성 영향 낮음", "A:H": "가용성 영향 높음",
};
function cvssVectorTip(vec) {
  const parts = String(vec || "").split("/").filter(Boolean);
  const ko = parts.map((p) => {
    if (/^CVSS:/i.test(p)) return `CVSS ${p.split(":")[1]} 기준`;
    return CVSS_PART_KO[p] || p;
  });
  return ko.length ? ko.join(" · ") : "CVSS 3.1 벡터";
}
function cweList(text) { return String(text || "").match(/CWE-\d+/gi) || []; }
function owaspList(text) {
  const t = String(text || "");
  const strict = t.match(/OWASP\s*A\d{2}(?::\d{4})?/gi) || [];
  if (strict.length) return strict;
  return t.match(/\bA\d{2}(?::\d{4})?\b/g) || [];
}
// 분류(CWE · OWASP) — abbr + title 툴팁.
function classifyHtml(cwe, owasp) {
  const parts = [];
  for (const c of cwe) {
    const id = (c.match(/\d+/) || [""])[0];
    const tip = CWE_TIPS[id] || "CWE(공통 약점 목록) 분류 번호 — 이 번호가 가리키는 취약점 유형";
    parts.push(`<abbr title="${esc(tip)}">${esc(c)}</abbr>`);
    tipSeen.add("cwe"); // B2: 이 문서에서 이미 툴팁을 건 용어는 다시 감싸지 않는다
  }
  for (const o of owasp) {
    const code = (o.match(/A\d{2}/i) || [""])[0].toUpperCase();
    const tip = OWASP_TIPS[code] || "OWASP Top 10 (2021) 분류";
    parts.push(`<abbr title="${esc(tip)}">${esc(o)}</abbr>`);
    tipSeen.add("owasp");
  }
  return parts.join('<span class="df-sep">·</span>');
}
// "CVSS: 9.8 (CVSS:3.1/AV:N/…) · CWE-89 · OWASP A03:2021" → 점수 · 벡터 · 분류
function splitScoreLine(content) {
  const s = String(content || "").trim();
  const scoreM = /^([\d]+(?:\.[\d]+)?)/.exec(s);
  const vecM = /\(([^)]*)\)/.exec(s);
  let rest = s;
  if (scoreM) rest = rest.slice(scoreM[0].length);
  if (vecM) rest = rest.replace(vecM[0], " ");
  return {
    score: scoreM ? scoreM[1] : null,
    vector: vecM ? vecM[1].trim() : null,
    cwe: cweList(rest),
    owasp: owaspList(rest),
  };
}
// E1) CVSS 한 줄을 '위험 점수' + '분류' 두 필드로 분해해 보여준다.
function scoreFieldsHtml(content) {
  const p = splitScoreLine(content);
  let html = "";
  if (p.score) {
    html += `<div class="diag-field field-score"><span class="df-label">위험 점수</span><span class="df-body">`
      + `<b class="cvss-num">${esc(p.score)}</b><span class="cvss-den">/ 10</span>`
      + (p.vector ? `<code class="cvss-vec" title="${esc(cvssVectorTip(p.vector))}">${esc(p.vector)}</code>` : "")
      + `</span></div>`;
  }
  const cls = classifyHtml(p.cwe, p.owasp);
  if (cls) {
    html += `<div class="diag-field field-score"><span class="df-label">분류</span><span class="df-body">${cls}</span></div>`;
  }
  if (!html) {
    html = `<div class="diag-field field-score"><span class="df-label">위험 점수</span><span class="df-body">${inlineMd(escHtml(content))}</span></div>`;
  }
  return html;
}
function diagFieldHtml(label, content) {
  const l = label.trim();
  const cls = l.includes("탈취") ? "field-loss" : l === "위험도" ? "field-risk" : l.includes("보완") ? "field-fix" : l === "검증" ? "field-verify" : l.includes("멘토") ? "field-mentor" : l === "증거" ? "field-evidence" : l === "재현" ? "field-repro" : (l === "CVSS" || l === "CWE" || l === "OWASP") ? "field-score" : "";
  // E1/E2) CVSS · CWE · OWASP — 점수·벡터·분류로 분해하고 툴팁을 붙인다.
  if (l === "CVSS") return scoreFieldsHtml(content);
  if (l === "CWE" || l === "OWASP") {
    const list = l === "OWASP" ? owaspList(content) : cweList(content);
    const cls2 = classifyHtml(l === "OWASP" ? [] : list, l === "OWASP" ? list : []);
    const body = cls2 || inlineMd(escHtml(content));
    return `<div class="diag-field field-score"><span class="df-label">분류</span><span class="df-body">${body}</span></div>`;
  }
  let body;
  if (l.includes("탈취")) {
    body = content.split(/[,，·、\/]/).map((s) => s.trim()).filter(Boolean)
      .map((s) => `<span class="dchip">${escHtml(s)}</span>`).join("");
  } else if (l.includes("멘토")) {
    body = `<span class="mentor-body">${inlineMd(escHtml(content))}</span>`;
  } else if (l === "증거") {
    body = `<pre class="ev-pre">${escHtml(content)}</pre>`;
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
      <span class="sim-title">단계별 미리보기 — <b>이렇게 하면 → 이렇게 된다</b></span>
      <span class="sim-ctl">
        <button class="sim-btn play" data-sim-act="play" title="전체 재생">▶ 재생</button>
        <button class="sim-btn" data-sim-act="step" title="다음 단계">+1 단계</button>
        <button class="sim-btn" data-sim-act="reset" title="처음부터">↺</button>
      </span>
      <span class="sim-prog">1/${steps.length}</span>
    </div>
    <div class="sim-track"><div class="sim-fill" style="width:${Math.round(100 / steps.length)}%"></div></div>
    <ol class="sim-steps">${rows}</ol>
    <div class="sim-note">이것은 실제 공격이 아니라 예상 과정을 보여주는 것입니다 — 아래 <b>검증 상태</b>([실증]/[징후]/[가정])에서 직접 확인 여부를 함께 보세요.</div>
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
      // D3) 7열 같은 넓은 표가 좁은 창에서 붕괴하지 않도록 가로 스크롤 컨테이너로 감싼다.
      out.push(`<div class="table-scroll">${html}</div>`);
      continue;
    }
    // 진단 필드 라인 (위험도:/진입점:/탈취 정보:/공격 방법:/멘토 노트:/증거:/재현:/영향:/보완:/검증:/CVSS:) — 들여쓰기 허용
    const fld = /^\s*(위험도|진입점|탈취\s*정보|공격\s*방법|멘토\s*노트|증거|재현|영향|보완|검증|우선순위|문제|CVSS|CWE|OWASP)[:：]\s*(.*)$/.exec(raw);
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
  const names = connected.map((p) => providerLabel(p.name)).join(", ");
  el.innerHTML = `<span class="s-dot ${n ? "on" : ""}"></span>`
    + (n
      ? `연결됨 ${n}/${PROVIDER_CATALOG.length} — ${esc(names)}`
      : `연결된 AI 모델 없음 (${PROVIDER_CATALOG.length}종 지원) — 아래에서 연결하세요`);
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
  if (a.yaml) setAuthPill("warn", "고급 설정 사용 중");
  else if (a.error) setAuthPill("err", "읽기 오류");
  else if (a.empty) setAuthPill("warn", "목록 비어 있음");
  else if (a.warn) setAuthPill("warn", "허용 0건");
  else setAuthPill("ok", `허용 ${allowList.length}개`);

  // YAML/경고 안내
  const yamlWarn = $("authYamlWarn");
  if (a.yaml) {
    yamlWarn.classList.remove("hidden");
    yamlWarn.innerHTML = `<svg class="ic ic-sm"><use href="#i-shield"/></svg><div><b>고급 설정 파일(YAML)을 사용 중입니다.</b> 여기에서 추가·제거해도 이 파일은 바뀌지 않습니다.<br/>⚙ 설정에서 auth 경로를 비우면 기본 목록(<code>${esc(a.default_path || "~/.redcell/authorization.list")}</code>)을 관리합니다.</div>`;
  } else if (a.warn) {
    yamlWarn.classList.remove("hidden");
    yamlWarn.innerHTML = `<svg class="ic ic-sm"><use href="#i-shield"/></svg><div><b>허용 대상이 없습니다.</b> 아래에서 주소를 추가하세요 — 추가하는 순간 점검할 수 있게 됩니다.</div>`;
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
    `<span class="auth-chip">점검 포트 <b>${a.ports && a.ports.length ? esc(a.ports.join(", ")) : "전체"}</b></span>`,
    `<span class="auth-chip">속도 제한 <b>초당 10회</b></span>`,
  ].join("");

  if (a.empty) showAuthError("점검 대상이 비어 있습니다 — 아래에서 주소를 추가하세요. 등록된 곳만 점검합니다.");
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
  if (!confirm(`"${target}" 을(를) 점검 대상에서 제외할까요?`)) return;
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
  const st = reportStats(statsDocs(docs));
  return { ...base, kind: "diag", pending: false, roots: st.roots, sev: st.sev, ver: st.ver, grade: st.grade };
}
function renderDashboard() {
  const body = $("dashBody");
  if (!body) return;
  const ordered = [...sessions].sort((a, b) => (String(b.updated_at || "").localeCompare(String(a.updated_at || ""))));
  if (!ordered.length) {
    body.innerHTML = `<div class="dash-empty">아직 기록이 없습니다 — 새로 시작해 보세요.</div>`;
    return;
  }
  const agg = ordered.map(dashSessionStats).reduce((a, st) => {
    a.total++;
    if (st.status === "done") a.done++;
    if (st.kind === "diag" && !st.pending) {
      a.diag++;
      a.roots += st.roots;
      for (const k of ["치명", "높음", "중간", "낮음"]) a.sev[k] += st.sev[k];
      for (const k of ["실증", "징후", "가정"]) a.ver[k] += st.ver[k];
      const rk = { "A": 0, "B": 1, "C": 2, "D": 3, "F": 4 }[st.grade.letter];
      if (rk > a.worstRank) { a.worstRank = rk; a.worst = st.grade; }
    }
    return a;
  }, { total: 0, done: 0, diag: 0, roots: 0, sev: { "치명": 0, "높음": 0, "중간": 0, "낮음": 0 }, ver: { "실증": 0, "징후": 0, "가정": 0 }, worstRank: -1, worst: null });
  const worst = agg.worst || { letter: "·", label: "—", cls: "g-none" };
  const STATUS_KO = { running: "진행 중", done: "완료", error: "오류", stopped: "중지됨", idle: "대기" };
  body.innerHTML = `
    <div class="dash-summary">
      <div class="ds-stat"><b>${agg.total}</b><span>작업</span></div>
      <div class="ds-stat"><b>${agg.diag}</b><span>진단 완료</span></div>
      <div class="ds-stat"><b>${agg.roots}</b><span>발견한 위험</span></div>
      <div class="ds-grade ${worst.cls}"><b>${worst.letter}</b><span>가장 위험한 등급</span></div>
      <div class="ds-crits">
        <span class="dc crit">치명 ${agg.sev["치명"]}</span><span class="dc high">높음 ${agg.sev["높음"]}</span>
        <span class="dc med">중간 ${agg.sev["중간"]}</span><span class="dc low">낮음 ${agg.sev["낮음"]}</span>
        <span class="dc v" title="직접 확인 = 직접 요청해 확인한 취약점 · 일부 확인 = 일부 정황만 확인됨 · 추측 = 코드·설명 기반 추론(미확인)">직접 ${agg.ver["실증"]} · 일부 ${agg.ver["징후"]} · 추측 ${agg.ver["가정"]}</span>
      </div>
    </div>
    ` + ordered.map((s) => {
    const st = dashSessionStats(s);
    const statusCls = ["running", "done", "error", "stopped", "idle"].includes(st.status) ? st.status : "idle";
    const statusKo = STATUS_KO[statusCls] || "대기";
    const title = st.kind === "diag" ? reportDisplayTitle(s) : `${((s.name || "").trim() || "작업")}${st.target ? `-${st.target}` : ""}`;
    let badge, meta;
    if (st.kind === "diag" && !st.pending) {
      badge = `<div class="dash-grade ${st.grade.cls}"><b>${st.grade.letter}</b><span>${st.grade.label}</span></div>`;
      meta = `<span class="dm-strong">위험 ${st.roots}개</span><i>치명 ${st.sev["치명"]}</i><i>높음 ${st.sev["높음"]}</i><i>중간 ${st.sev["중간"]}</i><i>낮음 ${st.sev["낮음"]}</i><i class="dm-v" title="직접 확인 = 직접 요청해 확인한 취약점 · 일부 확인 = 일부 정황만 확인됨 · 추측 = 코드·설명 기반 추론(미확인)">직접 ${st.ver["실증"]} · 일부 ${st.ver["징후"]} · 추측 ${st.ver["가정"]}</i>`;
    } else if (st.kind === "diag") {
      badge = `<div class="dash-grade g-run"><b><span class="dash-spin"></span></b><span>진단 중</span></div>`;
      meta = `<span class="dm-strong">리포트 만드는 중</span><i>${esc((s.goal && s.goal.slice(0, 60)) || "대기")}</i>`;
    } else {
      badge = `<div class="dash-grade g-none"><b>◇</b><span>작업</span></div>`;
      meta = `<i>${esc(st.goal)}</i>`;
    }
    return `<article class="dash-card" data-session="${s.id}">${badge}
        <div class="dash-main">
          <div class="dash-title"><b>${esc(title)}</b><span class="dash-status s-${statusCls}">${statusKo}</span></div>
          <div class="dash-meta">${meta}</div>
        </div>
        <div class="dash-side"><span class="dash-upd">${esc(st.updated)}</span>
          <button class="btn btn-ghost btn-xs dash-open">열기</button></div>
      </article>`;
  }).join("");
  // 카드 클릭 → 해당 세션 열기
  body.querySelectorAll("[data-session]").forEach((card) => {
    const sid = card.dataset.session;
    const open = () => { $("historyModal").classList.add("hidden"); selectSession(sid); };
    card.querySelector(".dash-open").onclick = open;
    card.onclick = (e) => { if (!e.target.closest(".dash-open")) open(); };
  });
}
// 전체 이력 모달: 진단 요약(모아보기)과 감사 로그를 한 곳에서 탭으로 전환.
async function openHistory(tab) {
  await ensureAllFull(); // 대시보드·감사 로그는 전 세션의 이벤트가 필요하다
  renderDashboard();            // 요약은 항상 최신으로 갱신
  document.getElementById("historyModal").classList.remove("hidden");
  setHistoryTab(tab || "summary");
}
function setHistoryTab(tab) {
  document.querySelectorAll("#historyModal .htab").forEach((t) => {
    const on = t.dataset.tab === tab;
    t.classList.toggle("active", on);
    t.setAttribute("aria-selected", on ? "true" : "false");
  });
  const sum = $("histPaneSummary"), aud = $("histPaneAudit"), rep = $("histPaneReports");
  if (sum) sum.classList.toggle("hidden", tab !== "summary");
  if (aud) aud.classList.toggle("hidden", tab !== "audit");
  if (rep) rep.classList.toggle("hidden", tab !== "reports");
  if (tab === "audit") renderAudit();
  if (tab === "reports") renderReports();
}

// ── 감사 로그: 포트폴리오 전체 보안 활동 이력 ────────────────────────────────
let auditFilter = "all";
function fmtAuditTs(ts) {
  if (ts == null) return "—";
  try {
    const d = new Date(ts);
    const p = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  } catch { return "—"; }
}
// 세션 이벤트에서 보안 감사 대상(인가·차단·발견) + 진단 완료 기록을 뽑는다.
function auditEntries() {
  const out = [];
  for (const s of sessions) {
    const target = `${s.host || ""}${s.port ? ":" + s.port : ""}` || "—";
    const evs = eventsOf(s);
    for (const e of evs) {
      if (e.type === "authorized") {
        out.push({ kind: "auth", sev: "ok", desc: e.text || `${target} 점검 대상 확인`, target, session: s.name || "(무제)", ts: e._ts != null ? e._ts : s.created_at, id: s.id });
      } else if (e.type === "blocked") {
        out.push({ kind: "block", sev: "block", desc: e.text || `${toolLabel(e.tool || "")} — 허용 범위 밖이라 멈춤`, target, session: s.name || "(무제)", ts: e._ts != null ? e._ts : s.created_at, id: s.id });
      } else if (e.type === "finding" && e.finding) {
        out.push({ kind: "finding", sev: e.finding.severity || "info", desc: e.finding.title, target, session: s.name || "(무제)", ts: e._ts != null ? e._ts : s.created_at, id: s.id });
      }
    }
    const doneEv = evs.find((x) => x.type === "done");
    if (s.diag && (s.status === "done" || doneEv)) {
      out.push({ kind: "diag", sev: "diag", desc: `보안 진단 완료 — ${target}`, target, session: s.name || "(무제)", ts: (doneEv && doneEv._ts != null ? doneEv._ts : s.updated_at) || s.created_at, id: s.id });
    }
  }
  return out.sort((a, b) => (b.ts || 0) - (a.ts || 0));
}
const AUDIT_ICON = { auth: "i-key", block: "i-ban", finding: "i-alert", diag: "i-check" };
const AUDIT_LABEL = { auth: "대상 등록", block: "차단", finding: "발견", diag: "진단 완료" };

// ── 리포트 모아보기: 발행 파일 + 파일 없는 기록을 세션별로 ──────────────────────
const REPORT_TAG_LABEL = { early: "1차", final: "최종", note: "메모", manual: "직접 저장" };
// 과거 기록 표시용 제목 — "{세션}-{주소} 진단 리포트" 형식으로 통일한다.
function sessionTarget(s) {
  return `${(s && s.host) || ""}${s && s.port ? ":" + s.port : ""}`;
}
function reportDisplayTitle(s) {
  const name = ((s && s.name) || "").trim();
  const tgt = sessionTarget(s);
  if (name && tgt) return `${name}-${tgt} 진단 리포트`;
  if (tgt) return `${tgt} 진단 리포트`;
  if (name) return `${name} 진단 기록`;
  return "제목 없음 진단 기록";
}
function reportDocRows(s) {
  // 발행 후보: report 표식 문서 + 긴 문서(추가 지시 후 정리 등). 짧은 메모는 제외.
  return resultDocs(s)
    .filter((d) => d.report || (d.text || "").length >= 200)
    .map((d) => ({ ...d, seqs: d.seqs && d.seqs.length ? d.seqs : (d.seq != null ? [d.seq] : []) }));
}
function fmtSize(n) {
  if (n == null) return "";
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}KB`;
  return `${(n / 1024 / 1024).toFixed(1)}MB`;
}
async function renderReports() {
  const body = $("reportList");
  const status = $("reportStatus");
  if (!body) return;
  body.innerHTML = `<div class="audit-empty">불러오는 중…</div>`;
  if (status) status.textContent = "";
  let files = [];
  try { files = await invoke("list_reports") || []; } catch (e) { files = []; }
  // 세션별 묶음
  const groups = new Map(); // sid -> { s, rows: [] }
  const manual = [];
  for (const f of files) {
    if (f.manual || !f.session_id) { manual.push(f); continue; }
    if (!groups.has(f.session_id)) groups.set(f.session_id, { s: sessions.find((x) => x.id === f.session_id) || null, rows: [] });
    groups.get(f.session_id).rows.push({ kind: "file", tag: f.tag, ts: f.ts, file: f.file, size: f.size });
  }
  // 파일 없는 기록 (오래된 세션·추가 지시 후 정리) — 열 때 저장된다.
  for (const s of sessions) {
    for (const d of reportDocRows(s)) {
      const tag = d.report || "note";
      const docTs = Math.round(((d.ts != null ? d.ts : 0) || 0) / 1000);
      const g = groups.get(s.id);
      const covered = g && g.rows.some((r) => r.kind === "file" && r.tag === tag && Math.abs((r.ts || 0) - docTs) < 300);
      if (covered) continue;
      if (!groups.has(s.id)) groups.set(s.id, { s, rows: [] });
      groups.get(s.id).rows.push({ kind: "event", tag, ts: docTs, seq: d.seq, seqs: d.seqs || [], size: (d.text || "").length });
    }
  }
  const ordered = [...groups.values()]
    .map((g) => ({ ...g, latest: Math.max(0, ...g.rows.map((r) => r.ts || 0)) }))
    .sort((a, b) => b.latest - a.latest);
  if (!ordered.length && !manual.length) {
    body.innerHTML = `<div class="audit-empty">아직 발행된 리포트가 없습니다 — 진단을 실행하면 1차·최종 리포트가 여기에 모입니다.</div>`;
    return;
  }
  const tagBadge = (tag) => `<span class="rp-tag rp-${tag}">${REPORT_TAG_LABEL[tag] || tag}</span>`;
  const rowHtml = (r, sid) => `
    <div class="rp-row">
      ${tagBadge(r.tag)}
      <div class="rp-main">
        <div class="rp-meta">${r.ts ? fmtAuditTs(r.ts * 1000) : "시간 없음"}${r.size != null ? ` · ${fmtSize(r.size)}` : ""}${r.kind === "event" ? " · 파일 없음" : ""}</div>
        ${r.file ? `<div class="rp-file" title="${esc(r.file)}">${esc(r.file.split(/[/\\]/).pop())}</div>` : ""}
      </div>
      <div class="rp-actions">
        <button class="btn btn-ghost btn-xs rp-open" data-kind="${r.kind}" data-sid="${esc(sid || "")}" data-seq="${r.seq ?? ""}" data-seqs="${esc((r.seqs || []).join(","))}" data-file="${esc(r.file || "")}">열기</button>
        <button class="btn btn-ghost btn-xs rp-reveal" data-kind="${r.kind}" data-sid="${esc(sid || "")}" data-seq="${r.seq ?? ""}" data-seqs="${esc((r.seqs || []).join(","))}" data-file="${esc(r.file || "")}" title="파일 위치를 탐색기에서 열기">폴더</button>
      </div>
    </div>`;
  body.innerHTML = ordered.map((g) => {
    const head = g.s ? reportDisplayTitle(g.s) : "(삭제된 작업) 진단 리포트";
    const rows = [...g.rows].sort((a, b) => (b.ts || 0) - (a.ts || 0)).map((r) => rowHtml(r, g.s ? g.s.id : "")).join("");
    return `<section class="rp-group"><header class="rp-group-head"><b>${esc(head)}</b></header>${rows}</section>`;
  }).join("") + (manual.length ? `<section class="rp-group"><header class="rp-group-head"><b>직접 저장한 파일</b></header>${
    manual.map((f) => rowHtml({ kind: "file", tag: "manual", ts: f.ts, file: f.file, size: f.size }, "")).join("")
  }</section>` : "");
  body.querySelectorAll(".rp-open").forEach((b) => { b.onclick = () => openReportRow(b.dataset, "open"); });
  body.querySelectorAll(".rp-reveal").forEach((b) => { b.onclick = () => openReportRow(b.dataset, "reveal"); });
}
async function openReportRow(ds, mode) {
  const status = $("reportStatus");
  const say = (t) => { if (status) status.textContent = t; };
  try {
    let file = ds.file || "";
    if (ds.kind === "event") {
      say("파일로 저장하는 중…");
      // 병합 문서는 조각 seq 전체를 넘겨 전문을 저장한다(첫 조각만 저장 방지).
      const seqs = String(ds.seqs || "").split(",").map((x) => Number(x)).filter((n) => Number.isFinite(n));
      const args = seqs.length > 1
        ? { session_id: ds.sid, seq: seqs[0], seqs }
        : { session_id: ds.sid, seq: Number(ds.seq) };
      file = await invoke("save_report_file", args);
      renderReports(); // 파일 행으로 바뀌었으므로 목록 새로고침
    }
    if (!file) { say("열 수 있는 파일이 없습니다."); return; }
    say(mode === "reveal" ? "폴더를 여는 중…" : "리포트를 여는 중…");
    await invoke("open_path", { path: file, mode });
    say("");
  } catch (e) { say(`열기 실패: ${e}`); }
}
async function openReportsFolder() {
  const status = $("reportStatus");
  try {
    const dir = await invoke("reports_path");
    await invoke("open_path", { path: dir, mode: "open" });
  } catch (e) { if (status) status.textContent = `열기 실패: ${e}`; }
}
function renderAudit() {
  const entries = auditEntries();
  const cnt = { all: entries.length, auth: 0, block: 0, finding: 0, diag: 0 };
  for (const e of entries) cnt[e.kind]++;
  $("auAll").textContent = cnt.all; $("auAuth").textContent = cnt.auth;
  $("auBlock").textContent = cnt.block; $("auFind").textContent = cnt.finding; $("auDiag").textContent = cnt.diag;
  document.querySelectorAll("#auditFilters .af-chip").forEach((c) => c.classList.toggle("active", c.dataset.f === auditFilter));
  const list = entries.filter((e) => auditFilter === "all" || e.kind === auditFilter);
  const body = $("auditList");
  if (!list.length) {
    body.innerHTML = `<div class="audit-empty">아직 기록이 없습니다 — 진단을 실행하면 대상 등록·발견·차단 기록이 쌓입니다.</div>`;
    return;
  }
  body.innerHTML = list.map((e) => {
    const icon = AUDIT_ICON[e.kind] || "i-file";
    const s = sessions.find((x) => x.id === e.id);
    const where = s && s.diag ? reportDisplayTitle(s) : `${e.session}${e.target && e.target !== "—" ? `-${e.target}` : ""}`;
    return `<div class="au-row au-${e.sev}">
      <span class="au-ic"><svg class="ic"><use href="#${icon}"/></svg></span>
      <div class="au-main">
        <div class="au-title"><span class="au-badge">${esc(AUDIT_LABEL[e.kind] || "기록")}</span> ${esc(e.desc)}</div>
        <div class="au-meta">${esc(where)}</div>
      </div>
      <span class="au-time">${fmtAuditTs(e.ts)}</span>
    </div>`;
  }).join("");
}

// ── 배선 ─────────────────────────────────────────────────────────────────────
// ── 과거 메모 패널 ────────────────────────────────────────────────────────────
async function loadMem() {
  const list = $("memList"), cnt = $("memCount");
  if (!list) return;
  const s = cur();
  let mem = { global: [], host: [] };
  try { mem = await invoke("get_memory", { host: (s && s.host) || "" }); } catch { /* 미리보기 */ }
  const all = [...(mem.host || []).map((m) => ({ ...m, scope: "이 주소" })), ...(mem.global || []).map((m) => ({ ...m, scope: "전체" }))];
  if (cnt) cnt.textContent = all.length ? `(${all.length}건 — 다음 진단에 자동 반영)` : "(없음)";
  list.innerHTML = all.length
    ? all.map((m) => `<div class="mem-item"><span class="mem-kind">${esc(m.scope)}${m.kind && m.kind !== "note" ? "·" + esc(m.kind) : ""}</span><span class="mem-text">${esc(m.text)}</span><button class="mem-del" data-id="${esc(m.id)}" title="삭제">✕</button></div>`).join("")
    : `<div class="placeholder">아직 메모가 없습니다 — 알게 된 사실을 남기면 다음 진단부터 반영됩니다.</div>`;
  list.querySelectorAll(".mem-del").forEach((b) => {
    b.onclick = async () => {
      try { await invoke("remove_memory", { id: b.dataset.id }); } catch (e) { toast("삭제 실패: " + e); return; }
      loadMem();
    };
  });
}
async function addMem() {
  const s = cur();
  const input = $("memText");
  const text = (input.value || "").trim();
  if (!text) { toast("메모 내용을 입력하세요."); return; }
  const scope = $("memScope").value;
  const host = scope === "global" ? "" : ((s && s.host) || "");
  try {
    await invoke("add_memory", { host, kind: "note", text });
  } catch (e) { toast("저장 실패: " + e); return; }
  input.value = "";
  loadMem();
}
function wire() {
  $("newSessionBtn").onclick = newSession;
  $("memAddBtn").onclick = addMem;
  $("memText").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); addMem(); } });
  $("emptyNewBtn").onclick = newSession;
  $("settingsBtn").onclick = openSettings;
  $("historyBtn").onclick = () => openHistory("summary");
  $("histClose").onclick = () => $("historyModal").classList.add("hidden");
  $("reportsFolderBtn").onclick = openReportsFolder;
  document.querySelectorAll("#historyModal .htab").forEach((t) => {
    t.onclick = () => setHistoryTab(t.dataset.tab);
  });
  $("auditFilters").addEventListener("click", (e) => {
    const chip = e.target.closest(".af-chip");
    if (!chip) return;
    auditFilter = chip.dataset.f;
    renderAudit();
  });
  $("settingsCancel").onclick = () => $("settingsModal").classList.add("hidden");
  $("settingsClose").onclick = () => $("settingsModal").classList.add("hidden");
  $("settingsSave").onclick = saveSettings;
  $("providerGoto").onclick = () => { $("providerModal").classList.add("hidden"); openSettings(); };
  $("providerClose").onclick = () => $("providerModal").classList.add("hidden");
  wireProviderCards();
  // 모달 공통: 바깥 클릭 / Esc 로 닫기
  ["settingsModal", "authModal", "providerModal", "historyModal", "dangerModal"].forEach((id) => {
    const m = $(id);
    if (!m) return;
    m.addEventListener("pointerdown", (e) => { if (e.target === m) { m.classList.add("hidden"); if (id === "dangerModal") cancelDangerPending(true); } });
  });
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    ["settingsModal", "authModal", "providerModal", "historyModal", "dangerModal"].forEach((id) => { const m = $(id); if (m && !m.classList.contains("hidden")) { m.classList.add("hidden"); if (id === "dangerModal") cancelDangerPending(true); } });
  });
  $("diagBtn").onclick = onDiagButton;
  $("dangerBtn").onclick = onDangerButton;
  // 진단 진행 방식 팝오버: 버튼 토글 · 바깥 클릭/Esc로 닫기
  const infoBtn = $("diagInfoBtn"), infoPop = $("diagInfoPop");
  if (infoBtn && infoPop) {
    const setInfo = (open) => {
      infoPop.classList.toggle("hidden", !open);
      infoBtn.setAttribute("aria-expanded", String(open));
      infoBtn.classList.toggle("open", open);
    };
    infoBtn.onclick = (e) => { e.stopPropagation(); setInfo(infoPop.classList.contains("hidden")); };
    infoPop.addEventListener("pointerdown", (e) => e.stopPropagation());
    document.addEventListener("pointerdown", (e) => {
      if (!infoPop.classList.contains("hidden") && !e.target.closest(".diag-info-wrap")) setInfo(false);
    });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") setInfo(false); });
  }
  $("dangerCancel").onclick = () => { $("dangerModal").classList.add("hidden"); cancelDangerPending(true); };
  $("dangerAck").addEventListener("change", (e) => { $("dangerConfirm").disabled = !e.target.checked; });
  $("dangerConfirm").onclick = confirmDanger;
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
      if (b) removeAuth(b.closest(".auth-item").dataset.target);
    });
  });
  const qg = $("quickGoals");
  if (qg) qg.addEventListener("click", (e) => {
    const b = e.target.closest(".chip");
    if (!b) return;
    $("chatInput").value = b.dataset.goal || b.textContent.trim();
    syncSendBtn();
    sendChat();
  });
  // 꼬리 따라가기 + 맨 아래로 버튼
  const capEl = document.querySelector(".capture");
  if (capEl) capEl.addEventListener("scroll", () => syncTailBtn(), { passive: true });
  const tailBtn = $("tailBtn");
  if (tailBtn) tailBtn.onclick = scrollCaptureBottom;
  // 라이브 필터 칩
  document.querySelectorAll("#liveFilter .lf-chip").forEach((chip) => {
    chip.onclick = () => {
      liveFilter = chip.dataset.f || "all";
      document.querySelectorAll("#liveFilter .lf-chip").forEach((c) => {
        const on = c === chip;
        c.classList.toggle("active", on);
        c.setAttribute("aria-selected", String(on));
      });
      renderCapture(cur());
    };
  });
  // 주소 입력에서 Enter → 진단 시작 (실행 중에는 중지 방지)
  ["shName", "shHost", "shPort"].forEach((id) => {
    const inp = $(id);
    if (inp) inp.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        if (cur() && cur().status === "running") return;
        const db = $("diagBtn");
        if (db) db.click();
      }
    });
  });
  // 보내기 버튼 활성 상태
  const chatInputEl = $("chatInput");
  if (chatInputEl) chatInputEl.addEventListener("input", syncSendBtn);
  syncSendBtn();
  ["shName", "shHost", "shPort", "shProvider", "shEngine", "shCookie"].forEach((id) => $(id) && $(id).addEventListener("change", () => persistHeader()));
  document.querySelectorAll(".subtab").forEach((btn) => { btn.onclick = () => switchView(btn.dataset.view); });
  // 시뮬레이션 플레이어 컨트롤 (결과 탭 전체 위임 — 재렌더 후에도 유지)
  const rb = $("resultsBody");
  // 리포트 본문을 스크롤하면 상단 요약을 접어 본문 공간을 넓게 쓴다.
  if (rb) rb.addEventListener("scroll", onResultsScroll, { passive: true });
  if (rb) rb.addEventListener("click", (e) => {
    // 개별 결과 내보내기 (카드마다 복사/PDF/MD/HTML)
    const rdExp = e.target.closest(".rd-exp");
    if (rdExp) {
      e.preventDefault();
      const ix = rdExp.dataset.ix;
      const act = rdExp.dataset.act;
      if (act === "copy") copySegment(ix, rdExp);
      else if (act === "pdf") printSegment(ix, rdExp);
      else if (act === "md") exportSegment(ix, false, rdExp);
      else if (act === "html") exportSegment(ix, true, rdExp);
      return;
    }
    // '자동 보완' 조치 1클릭 지시 → 에이전트에 보완 목표 전달
    const ns = e.target.closest(".ns-run");
    if (ns) {
      e.preventDefault();
      const goal = ns.dataset.goal || "";
      const s = cur();
      if (s && !s.host) { toast("먼저 위에 주소를 입력하세요."); return; }
      if (!activeProvider()) { showProviderModal(); return; }
      const ci = $("chatInput");
      if (ci) ci.value = goal ? `이 문제를 고쳐줘: ${goal}` : goal;
      sendChat();
      return;
    }
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
    if (status === "stopped") pushAssistant(sessionId, "실행을 중지했습니다. 다시 시작하려면 진단 시작을 누르세요.");
  });
}

// ── 온보딩 히어로: 세션이 없으면 URL 입력 첫 화면 ─────────────────────────────
function syncHero() {
  const hero = $("onboardHero"); if (!hero) return;
  hero.classList.toggle("hidden", sessions.length > 0);
  if (sessions.length === 0) syncObProvider();
}
function obError(msg) {
  const el = $("obError"); if (!el) return;
  if (!msg) { el.classList.add("hidden"); el.textContent = ""; return; }
  el.classList.remove("hidden"); el.textContent = msg;
}
function syncObProvider() {
  const sel = $("obProvider"); if (!sel) return;
  const connected = PROVIDER_CATALOG.filter(providerConnected);
  const prev = sel.value || settings.default_provider || "";
  // A4) 옵션 텍스트는 사람 말로 (값은 그대로 유지 — 내부 이름이 화면에 새지 않게).
  sel.innerHTML = `<option value="">— AI 모델을 고르세요 —</option>`
    + connected.map((p) => `<option value="${esc(p.name)}">${esc(providerLabel(p.name))} ✅</option>`).join("");
  if (prev && connected.some((p) => p.name === prev)) sel.value = prev;
  if (!connected.length) {
    sel.insertAdjacentHTML("beforeend", `<option value="__setup">먼저 연결해 주세요</option>`);
  }
  syncObSetupCard();
}
// A1) AI 모델이 하나도 연결돼 있지 않으면 — '진단 시작' 을 누르기 전부터 안내 카드를 띄운다.
function syncObSetupCard() {
  const el = $("obSetup"); if (!el) return;
  const connected = PROVIDER_CATALOG.filter(providerConnected);
  if (connected.length) { el.classList.add("hidden"); el.innerHTML = ""; return; }
  el.classList.remove("hidden");
  el.innerHTML = `
    <div class="hs-txt">
      <b>시작하려면 AI 모델 하나를 연결해야 해요</b>
      <span>설정(⚙) → 모델 연결에서 API 키만 입력하면 1분이면 됩니다.</span>
    </div>
    <button id="obSetupBtn" class="btn btn-primary">AI 모델 연결하기</button>`;
  const btn = $("obSetupBtn");
  if (btn) btn.onclick = () => openSettings(); // 설정 모달(기존 동작) 재사용
}
async function obStart() {
  const raw = $("obUrl").value.trim();
  if (!raw) { obError("진단할 URL을 입력하세요. (예: https://example.com)"); $("obUrl").focus(); return; }
  const norm = normalizeTargetInput(raw);
  if (!norm.host) { obError("URL에서 대상을 읽지 못했습니다. https:// 로 시작하는 주소를 입력하세요."); return; }
  let prov = $("obProvider").value || settings.default_provider || "";
  if (!prov || prov === "__setup") {
    // A2) '진단 시작' 을 눌렀는데 모델이 없으면 — 왜 멈췄는지 정직하게 말한다.
    const msg = "AI 모델 연결이 필요해요 — 설정(⚙) → 모델 연결에서 API 키를 입력해 주세요.";
    obError(msg);
    toast(msg);
    showProviderModal();
    return;
  }
  const eng = $("obEngine").value === "prime" ? "prime" : "";
  if (eng === "prime" && enginesInfo && !primeAvailable()) { obError("심화 검사 엔진이 설치돼 있지 않습니다. 기본 검사 엔진을 선택하거나 심화 검사 엔진을 먼저 설치하세요."); return; }
  obError(null);
  const port = norm.port ? parseInt(norm.port, 10) : null;
  const s = await invoke("create_session", {
    name: norm.host, host: norm.host,
    port: Number.isInteger(port) && port > 0 && port <= 65535 ? port : null,
    goal: DEFAULT_DIAG_GOAL, provider: prov, mode: "prime", diag: true, deep: true, engine: eng,
  });
  sessions.unshift(s);
  if (s) s.__full = true;
  activeId = s.id;
  renderTabs();
  renderActive();
  await ensureTargetAuthorized();
  await beginDeepDiagnosis(cur());
}
function wireOb() {
  const btn = $("obDiag"); if (!btn) return;
  btn.onclick = obStart;
  $("obUrl").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); obStart(); } });
  $("obProvider").addEventListener("change", (e) => { if (e.target.value === "__setup") { e.target.value = ""; showProviderModal(); } });
  const eng = $("obEngine");
  if (eng) eng.addEventListener("change", syncEngineHint);
  $("obSkip").onclick = newSession;
}

// ── 엔진 상태: pi + prime-agent(직접 실행) 감지 표시 ────────────────────────────
let enginesInfo = null;
function engineBadge(ok, name, detail) {
  return `<span class="eng-pill ${ok ? "on" : "off"}"><i></i>${esc(name)}<em>${esc(detail)}</em></span>`;
}
function primeAvailable() {
  return !!(enginesInfo && enginesInfo.prime_agent && enginesInfo.prime_agent.found);
}
// A3) 엔진 이름을 사람 말로 — 내부 식별자(pi · prime-agent)는 화면에 내보내지 않는다.
const ENGINE_LABELS = { pi: "기본 검사 엔진", prime: "심화 검사 엔진" };
function syncEngineSelects() {
  const ok = primeAvailable() || !enginesInfo; // 감지 전에는 막지 않음
  ["shEngine", "obEngine"].forEach((id) => {
    const sel = $(id); if (!sel) return;
    const base = [...sel.options].find((o) => o.value === "pi");
    if (base) base.textContent = ENGINE_LABELS.pi;
    const opt = [...sel.options].find((o) => o.value === "prime");
    if (opt) {
      opt.disabled = !ok;
      opt.textContent = ok ? ENGINE_LABELS.prime : `${ENGINE_LABELS.prime} (미설치)`;
      if (!ok && sel.value === "prime") sel.value = id === "obEngine" ? "" : "pi";
    }
    sel.title = ok
      ? "진단 엔진 — 잘 모르면 '자동(권장)' 또는 기본 검사 엔진 그대로 두세요"
      : "심화 검사 엔진이 설치돼 있지 않아 기본 엔진으로 진행합니다";
  });
  syncEngineHint();
}
// 엔진 선택 아래 한 줄 설명 — title(호버)만으로는 키보드·터치 사용자가 못 읽는다.
function syncEngineHint() {
  const el = $("obEngineHint"); if (!el) return;
  const sel = $("obEngine");
  const deep = sel && sel.value === "prime";
  el.textContent = deep
    ? "심화 엔진은 더 깊게 여러 관점에서 봅니다 — 시간이 조금 더 걸릴 수 있어요."
    : "기본 엔진이면 충분해요. 심화 엔진은 더 깊게 여러 관점에서 봅니다.";
}
async function refreshEngines() {
  let info = null;
  try { info = await invoke("detect_engines"); } catch { /* 구 백엔드·프리뷰 폴백 */ }
  enginesInfo = info;
  const pv = info && info.prime_agent && info.prime_agent.version;
  const piv = info && info.pi && info.pi.version;
  const piStale = info && info.pi && info.pi.found && info.pi.satisfies_min === false;
  const primeStale = info && info.prime_agent && info.prime_agent.found && info.prime_agent.satisfies_min === false;
  const piLabel = !(info.pi && info.pi.found)
    ? "미설치 — npm i -g @earendil-works/pi-coding-agent"
    : (piStale ? `구버전 ${piv || ""} (최소 ${info.pi.min}) — 업데이트 권장` : `연결됨${piv && piv !== "미확인" ? ` (${piv})` : ""}`);
  const primeLabel = !(info.prime_agent && info.prime_agent.found)
    ? "미설치(선택)"
    : (primeStale ? `구버전 ${pv || ""} (최소 ${info.prime_agent.min}) — 업데이트 권장` : `직접 실행 가능${pv ? ` (${pv})` : ""}`);
  const html = info
    ? engineBadge(!!(info.pi && info.pi.found), ENGINE_LABELS.pi, piLabel)
      + engineBadge(!!(info.prime_agent && info.prime_agent.found), ENGINE_LABELS.prime, primeLabel)
    : "";
  const ob = $("obEngines"); if (ob) ob.innerHTML = html;
  const st = $("engineStatus"); if (st) st.innerHTML = html || '<span class="eng-dim">엔진 정보를 가져오지 못했습니다</span>';
  syncEngineSelects();
}

async function boot() {
  if (!TAURI) {
    document.body.innerHTML = '<div class="placeholder" style="margin-top:80px">이 페이지는 Tauri 앱 안에서 실행해야 합니다.<br/>터미널에서 <code>cargo tauri dev</code> 로 띄우세요.</div>';
    return;
  }
  wire();
  wireOb();
  switchView("live");
  settings = await invoke("get_settings");
  sessions = await invoke("list_sessions");
  try { await invoke("backfill_reports"); } catch { /* 미리보기·구버전은 무시 */ }
  activeId = sessions.length ? sessions[0].id : null;
  if (activeId) {
    // list_sessions 는 요약만 주므로, 처음 열릴 세션은 전체를 로드한다.
    await selectSession(activeId);
  } else {
    renderTabs();
    renderActive();
  }
  await listenEngagement();
  await refreshProviders();
  syncObProvider();
  await refreshEngines();
}

window.addEventListener("DOMContentLoaded", boot);
