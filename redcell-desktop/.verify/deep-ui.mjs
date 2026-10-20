// New-UI smoke: hero wiring, deep-diagnosis worker board, mentor/evidence rendering.
import { chromium } from "playwright";

const URL = process.env.PREVIEW_URL || "http://localhost:5173/";
const failures = [];
const browser = await chromium.launch({ args: ["--no-sandbox"] });
const ctx = await browser.newContext({ viewport: { width: 1360, height: 860 } });
const page = await ctx.newPage();
page.on("pageerror", (e) => failures.push(`pageerror: ${e.message}`));
await page.goto(URL, { waitUntil: "networkidle" });
await page.evaluate(() => localStorage.clear());
await page.reload({ waitUntil: "networkidle" });

// 1) hero exists, hidden while sessions exist; force-show and check validation wiring.
const hero = await page.evaluate(() => {
  const h = document.getElementById("onboardHero");
  const out = { present: !!h, hiddenInitially: h.classList.contains("hidden") };
  h.classList.remove("hidden");
  document.getElementById("obUrl").value = "";
  document.getElementById("obDiag").click();
  const err = document.getElementById("obError");
  out.errVisible = !err.classList.contains("hidden");
  out.errText = err.textContent;
  out.providerOptions = document.getElementById("obProvider").options.length;
  out.engines = document.getElementById("obEngines").textContent;
  h.classList.add("hidden");
  return out;
});
console.log("hero", JSON.stringify(hero));
if (!hero.present || !hero.hiddenInitially) failures.push("hero missing or visible with sessions");
if (!hero.errVisible || !/URL/.test(hero.errText)) failures.push("hero URL validation missing");
if (hero.providerOptions < 1) failures.push("hero provider select empty");
if (!/pi-coding-agent/.test(hero.engines)) failures.push("hero engines missing pi badge");

// 2) mentor note + evidence render in the diag demo report.
const tab = page.locator(".tab", { hasText: "진단" }).first();
await tab.locator(".tname").click().catch(async () => { await tab.click(); });
await page.locator('.subtab[data-view="results"]').click();
await page.waitForTimeout(300);
const fields = await page.evaluate(() => ({
  mentor: document.querySelectorAll("#resultsBody .field-mentor").length,
  evidence: document.querySelectorAll("#resultsBody .field-evidence .ev-pre").length,
}));
console.log("fields", JSON.stringify(fields));
if (fields.mentor < 1) failures.push("mentor note not rendered");
if (fields.evidence < 1) failures.push("evidence block not rendered");

// 3) deep diagnosis via the real diag-button path: provider -> run -> chips -> done.
const plain = page.locator(".tab", { hasText: "vulnlab-web" }).first();
await plain.locator(".tname").click().catch(async () => { await plain.click(); });
await page.locator('.subtab[data-view="live"]').click();
await page.evaluate(() => {
  const sel = document.getElementById("shProvider");
  if (![...sel.options].some((o) => o.value === "anthropic")) {
    sel.insertAdjacentHTML("beforeend", `<option value="anthropic">anthropic</option>`);
  }
  sel.value = "anthropic";
});
await page.locator("#diagBtn").click();
await page.waitForFunction(() => document.querySelectorAll("#workerBar .wk-chip").length === 6, null, { timeout: 10000 });
await page.waitForTimeout(300);
const chipsRunning = await page.evaluate(() => ({
  total: document.querySelectorAll("#workerBar .wk-chip").length,
  running: document.querySelectorAll("#workerBar .wk-chip.run").length,
  badge: document.getElementById("statusBadge").textContent,
  sweep: document.getElementById("capBody").textContent,
}));
console.log("chips-running", JSON.stringify(chipsRunning));
if (chipsRunning.total !== 6) failures.push(`expected 6 chips (P0+5 workers), got ${chipsRunning.total}`);
if (!/P0 스윕 — 프로브 \d+개/.test(chipsRunning.sweep)) failures.push("P0 sweep summary note missing");
await page.waitForFunction(() => document.querySelectorAll("#workerBar .wk-chip.ok").length === 6 && document.getElementById("statusBadge").textContent === "done", null, { timeout: 20000 });
const chipsDone = await page.evaluate(() => ({
  ok: document.querySelectorAll("#workerBar .wk-chip.ok").length,
  badge: document.getElementById("statusBadge").textContent,
  chat: document.getElementById("chatMessages").textContent,
}));
console.log("chips-done", JSON.stringify({ ok: chipsDone.ok, badge: chipsDone.badge }));
if (chipsDone.ok !== 6) failures.push(`expected 6 done chips, got ${chipsDone.ok}`);
if (chipsDone.badge !== "done") failures.push(`expected done badge, got ${chipsDone.badge}`);
if (!/심층 진단 완료/.test(chipsDone.chat)) failures.push("deep-done chat summary missing");
// 4) final merged report renders as diag cards with mentor/evidence.
await page.locator('.subtab[data-view="results"]').click();
await page.waitForTimeout(400);
const merged = await page.evaluate(() => ({
  roots: document.querySelectorAll("#resultsBody .md-card.is-root").length,
  mentor: document.querySelectorAll("#resultsBody .field-mentor").length,
  evidence: document.querySelectorAll("#resultsBody .field-evidence .ev-pre").length,
}));
console.log("merged", JSON.stringify(merged));
if (merged.roots < 3) failures.push(`expected >=3 root cards, got ${merged.roots}`);
if (merged.mentor < 1 || merged.evidence < 1) failures.push("merged report missing mentor/evidence");
// 5) engine selection: prime-agent option enabled, persisted, and used for the run.
const engines = await page.evaluate(() => ({
  sh: !!document.getElementById("shEngine"),
  ob: !!document.getElementById("obEngine"),
  primeEnabled: (() => { const o = [...document.getElementById("shEngine").options].find((x) => x.value === "prime"); return o && !o.disabled; })(),
  badge: document.getElementById("obEngines").textContent,
}));
console.log("engines", JSON.stringify(engines));
if (!engines.sh || !engines.ob) failures.push("engine selects missing");
if (!engines.primeEnabled) failures.push("prime option should be enabled in mock");
if (!/직접 실행 가능/.test(engines.badge)) failures.push("prime direct-run badge missing");
// 6) prime-engine deep run on the same tab: prime-툴 notes stream, done badge, report intact.
await page.locator('.subtab[data-view="live"]').click();
await page.evaluate(() => {
  const sel = document.getElementById("shEngine");
  sel.value = "prime";
  sel.dispatchEvent(new Event("change", { bubbles: true }));
});
await page.waitForTimeout(300);
await page.locator("#diagBtn").click();
// stale ok-chips from the previous run: first observe the new run flipping chips to running…
await page.waitForFunction(() => document.querySelectorAll("#workerBar .wk-chip.run").length >= 1, null, { timeout: 15000 });
// …then wait for the new run to finish (chips ok + done badge).
await page.waitForFunction(() => document.querySelectorAll("#workerBar .wk-chip.ok").length === 6 && document.getElementById("statusBadge").textContent === "done", null, { timeout: 20000 });
await page.waitForTimeout(300);
const prime = await page.evaluate(() => ({
  capture: document.getElementById("capBody").textContent,
  badge: document.getElementById("statusBadge").textContent,
  engine: document.getElementById("shEngine").value,
  chat: document.getElementById("chatMessages").textContent,
}));
console.log("prime-run", JSON.stringify({ badge: prime.badge, engine: prime.engine, hasPrimeTool: /prime-툴/.test(prime.capture) }));
if (!/prime-툴/.test(prime.capture)) failures.push("prime-툴 notes missing in prime run");
if (prime.badge !== "done") failures.push(`expected done badge in prime run, got ${prime.badge}`);
if (prime.engine !== "prime") failures.push("engine select did not persist prime");
if (!/prime-agent/.test(prime.chat)) failures.push("prime engine label missing in chat");
await page.locator('.subtab[data-view="results"]').click();
await page.waitForTimeout(400);
const primeRoots = await page.evaluate(() => document.querySelectorAll("#resultsBody .md-card.is-root").length);
if (primeRoots < 3) failures.push(`expected >=3 root cards after prime run, got ${primeRoots}`);

// 7) auth-cookie run: cookie input persists, P0 sweep note shows (인증) + injection trial.
await page.locator('.subtab[data-view="live"]').click();
await page.evaluate(() => {
  const c = document.getElementById("shCookie");
  if (!c) throw new Error("shCookie missing");
  c.value = "SESS=preview-demo";
  c.dispatchEvent(new Event("change", { bubbles: true }));
});
await page.waitForTimeout(300);
await page.locator("#diagBtn").click();
await page.waitForFunction(() => document.querySelectorAll("#workerBar .wk-chip.run").length >= 1, null, { timeout: 15000 });
await page.waitForFunction(() => document.querySelectorAll("#workerBar .wk-chip.ok").length === 6 && document.getElementById("statusBadge").textContent === "done", null, { timeout: 20000 });
await page.waitForTimeout(300);
const auth = await page.evaluate(() => ({
  capture: document.getElementById("capBody").textContent,
  badge: document.getElementById("statusBadge").textContent,
  cookie: document.getElementById("shCookie").value,
}));
console.log("auth-run", JSON.stringify({ badge: auth.badge, cookie: auth.cookie, hasAuthSweep: /P0 스윕\(인증\)/.test(auth.capture) }));
if (!/P0 스윕\(인증\)/.test(auth.capture)) failures.push("auth P0 sweep note missing (인증)");
if (!/injection 시도/.test(auth.capture)) failures.push("login injection trial note missing in auth run");
if (auth.badge !== "done") failures.push(`expected done badge in auth run, got ${auth.badge}`);
if (auth.cookie !== "SESS=preview-demo") failures.push("cookie input did not persist value");
// 8) danger consent modal: gated confirm -> armed -> danger run -> revoke.
await page.locator('.subtab[data-view="live"]').click();
await page.locator("#dangerBtn").click();
await page.waitForTimeout(300);
const modal0 = await page.evaluate(() => ({
  visible: !document.getElementById("dangerModal").classList.contains("hidden"),
  confirmDisabled: document.getElementById("dangerConfirm").disabled,
  target: document.getElementById("dangerTarget").textContent,
}));
console.log("danger-modal", JSON.stringify(modal0));
if (!modal0.visible) failures.push("danger modal did not open");
if (!modal0.confirmDisabled) failures.push("danger confirm should be disabled before ack");
if (!/vulnlab/.test(modal0.target)) failures.push(`danger target wrong: ${modal0.target}`);
await page.locator("#dangerAck").check();
await page.locator("#dangerConfirm").click();
await page.waitForTimeout(300);
const armed = await page.evaluate(() => ({
  hidden: document.getElementById("dangerModal").classList.contains("hidden"),
  label: document.getElementById("dangerLabel").textContent,
  cls: document.getElementById("dangerBtn").className,
}));
if (!armed.hidden) failures.push("danger modal did not close on confirm");
if (armed.label !== "파괴적: 켬" || !/armed/.test(armed.cls)) failures.push(`danger button not armed: ${armed.label}`);
await page.locator("#diagBtn").click();
await page.waitForFunction(() => document.querySelectorAll("#workerBar .wk-chip.run").length >= 1, null, { timeout: 15000 });
await page.waitForFunction(() => document.querySelectorAll("#workerBar .wk-chip.ok").length === 6 && document.getElementById("statusBadge").textContent === "done", null, { timeout: 20000 });
await page.waitForTimeout(300);
const dg = await page.evaluate(() => ({ capture: document.getElementById("capBody").textContent }));
console.log("danger-run", JSON.stringify({ hasDangerSweep: /파괴적 동의/.test(dg.capture) }));
if (!/P0 스윕\(인증\)\(파괴적 동의\)/.test(dg.capture)) failures.push("danger P0 sweep note missing (파괴적 동의)");
if (!/P0 파괴적 프로브 실행/.test(dg.capture)) failures.push("danger probe warning note missing");
if (!/P0 파괴적 결과/.test(dg.capture)) failures.push("danger result note missing");
await page.locator("#dangerBtn").click();
await page.waitForTimeout(300);
const revoked = await page.evaluate(() => document.getElementById("dangerLabel").textContent);
if (revoked !== "파괴적: 끔") failures.push(`danger revoke failed: ${revoked}`);
// 9) dynamic risk guardrail: destructive chat instruction -> risk modal -> consent -> run -> stop.
await page.locator('.subtab[data-view="live"]').click();
await page.locator("#chatInput").fill("서버 재부팅해줘");
await page.locator("#chatSend").click();
await page.waitForFunction(() => !document.getElementById("dangerModal").classList.contains("hidden"), null, { timeout: 8000 });
await page.waitForTimeout(300);
const risk = await page.evaluate(() => ({
  title: document.getElementById("dangerTitle").textContent,
  level: document.getElementById("riskLevel").textContent,
  concerns: document.getElementById("riskConcerns").textContent,
  flags: document.getElementById("riskFlags").textContent,
  confirmDisabled: document.getElementById("dangerConfirm").disabled,
  badge: document.getElementById("statusBadge").textContent,
}));
console.log("risk-modal", JSON.stringify({ title: risk.title, level: risk.level, flags: risk.flags }));
if (risk.title !== "파괴적 지시 확인") failures.push(`risk modal title wrong: ${risk.title}`);
if (risk.level !== "치명") failures.push(`risk level wrong: ${risk.level}`);
if (!/시스템 중단/.test(risk.concerns)) failures.push("risk concern missing");
if (!/서비스 중단 가능/.test(risk.flags)) failures.push("shutdown flag missing");
if (!risk.confirmDisabled) failures.push("risk confirm should be gated");
if (risk.badge === "running" || risk.badge === "error") failures.push(`badge should await decision, got ${risk.badge}`);
await page.locator("#dangerAck").check();
await page.locator("#dangerConfirm").click();
await page.waitForFunction(() => document.getElementById("statusBadge").textContent === "running", null, { timeout: 8000 });
const armedRun = await page.evaluate(() => document.getElementById("dangerLabel").textContent);
if (armedRun !== "파괴적: 켬") failures.push("consent did not arm session");
await page.locator("#diagBtn").click(); // 실행 중 → 중지
await page.waitForFunction(() => document.getElementById("statusBadge").textContent === "stopped", null, { timeout: 8000 });
await page.locator("#dangerBtn").click(); // 철회
await page.waitForTimeout(300);
// 10) benign instruction must NOT trigger the modal.
await page.locator("#chatInput").fill("합격자 목록 파일로 뽑아줘");
await page.locator("#chatSend").click();
await page.waitForFunction(() => document.getElementById("statusBadge").textContent === "running", null, { timeout: 8000 });
await page.waitForTimeout(500);
const benign = await page.evaluate(() => ({
  modalHidden: document.getElementById("dangerModal").classList.contains("hidden"),
  badge: document.getElementById("statusBadge").textContent,
}));
console.log("benign-run", JSON.stringify(benign));
if (!benign.modalHidden) failures.push("benign instruction wrongly triggered risk modal");
if (benign.badge !== "running") failures.push(`benign run did not start: ${benign.badge}`);
await page.locator("#diagBtn").click();
await page.waitForFunction(() => ["stopped", "done"].includes(document.getElementById("statusBadge").textContent), null, { timeout: 8000 });
await page.screenshot({ path: "/tmp/ui-shot/new-ui-live.png" });
await ctx.close();
await browser.close();
if (failures.length) { console.log("FAIL\n" + failures.join("\n")); process.exit(1); }
console.log("NEW-UI CHECKS PASSED");
